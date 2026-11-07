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
  so granting never narrows what a principal holds. Conditions are told apart by their length and
  64-bit hash, so one whose condition shares both with another's of the same grant otherwise is
  refused with `ErrInvalid`. Each has an `ID`, who made it and when, and who last changed it.
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
  hour's. An exemption from a deny is held so too: what a deny binding the actor removes, the actor
  holds only while the deny exempts it, through the latest of its paths to the groups it exempts,
  or its membership where it exempts the tenant's members, unless it binds the actor no longer by
  then, and hands on no longer; an exemption by the actor's identity, or by a path that never ends,
  bounds nothing. A deny's condition is decided as of the change, as every condition is: a grant's
  can be handed on with it, as the actor hands on what it holds under one only under the same, but
  a deny's can't, so one that holds only from a later time, as by reading `request.time`, bounds
  nothing handed on before then. Time-limit an exception to a deny with a place that ends, not a
  condition. A grant outlives the actor's power to change grants, though: a power held for an hour
  grants for good what the actor holds for good, and the roles a role it holds lists, which it
  needn't hold. Put expiries on roles that list none. A change granting a role until many times,
  as to many members each until its own, decides it once for each time that the longest lasting of
  a kind of the actor's grants ends among them, not for each grant: a kind is a role held through
  the actor or any of its groups, through the tenant's members, or through the public, so grants
  of one role to its many groups, each ending at its own hour, are one kind.
- **Creators:** nothing is owned. The host gives whoever creates a resource a role on it with
  `Import`, as an actor it names, in the same transaction through `WithTx`.

## Lists

Store each resource's `authz.Path(resource)`, its own key first and then its containers' and the
tenant's, in a `text[]` column with a GIN index. `Filter` returns a condition for the host's own
query, which reads the grants in the same statement as the rows, so sorting and pagination work and
nothing changes between deciding and reading. It keeps only the rows whose own key is of the listed
type, so one table can hold resources of several types, where a grant on a container reaches every
row under it, of any type. The planner can't count a type's rows by their paths, and counts the
condition as keeping as many as of a table of one type: listing a type from a table of several, test
a column of the type too, whose statistics count them, and index it after the tenant and before what
pages sort by, as `(tenant, type, id)`, or a sorted page of a type of few rows reads the rows of
every type until it is full. A condition holds for the query it was built for: it fixes the time,
the subject's label holding and what the constraints answered, so build one for each query; the
query decides no earlier than the latest time `DeleteExpired` deleted by that it sees, keeps no row
where that is past the database's clock, where a check is refused (Expiry), and with the label
column keeps no row once that is as late as the first time after `Filter` read the holding that the
subject's membership, or its last path to one of its groups, ended. It compares the
tenant and keys byte for byte, as `Authorize` does, whatever the columns' collation, in
which their indexes still serve. The subject's grants are matched through the path's index, whose
cost for each row it finds grows with their number. Past a few on resources of the listed type, or
past 128 on containers and the tenant, as one holding a grant on everything it created does, each of
a row's keys is looked up among them instead, so a row costs a few lookups however many it holds; no
index serves that, so the query then reads every row of the tenant its other conditions keep.
Denies, on resources and containers alike, are looked up so whatever their number, and of those
naming the subject or its groups only theirs are read; denies naming the public or the tenant's
members are read by type while the listed types hold few denies, or as of a time while history holds
few versions of denies there, deleted ones too, and otherwise every one in the tenant is.
`Reachable` returns the same as scopes, for resources kept in another store, and of the listed type
alone: a scope reaches everything under it, so a store holding several types keeps to that type
itself. Both search one tenant, and count only unconditional grants: `Reach.Conditional` names the
scopes conditional ones reach, to check one by one. The condition reads the package's tables in the
host's statement, which the host plans, so the package can't pin its plan as it pins its own reads
(Planner settings): a plan the host's session made while those tables were small, and keeps, reads
each of them whole, once for each type and key the condition looks up, as a page read whole costs
less than descending any index. Run the query with sequential scans off for it alone, as
`SET LOCAL enable_seqscan = off` before it does in a transaction of its own, whose end puts the
setting back as the session had it, or in a savepoint rolled back to after it, which puts it back
as the transaction had it; not `RESET enable_seqscan` after it, which sets the session's own to what
it started with, dropping a value the session set, as a pool can for each connection it opens. Or
plan it again once the tables have grown, as an analysis of them does: under a plan cached while
they held a few rows, a list read 43,736 pages of grants and 4,502 of denies beside 20,000 of each.

## Policies

- **Custom roles:** a tenant defines its own with `SetRole`, ids starting `custom.`, from the
  permissions and types the built-in roles use. Defining one needs `rbac.DefineRoles` on the tenant
  and everything the role gives across it. Redefining one so that its grants give more asks
  `ValidateGrant` about each grant and eligibility it widens, as the role will be, and the host
  refusing one refuses the redefinition, as is one giving more label values where a condition of its
  grants on the tenant reading the action would then cost a check more than it may spend; an actor a
  label of a scope its grants are on, as `Config.ResourceOf` gives it, refuses, or a deny on that
  scope's path keeps from changing grants there, can neither change what its grants give nor
  delete it, nor widen it where a deny there, or where a role listing it, or listing one that does,
  is granted where its holders may then grant it, removes a permission it would give or the power
  to grant it, or a constraint does on that scope, as it would stop `Apply` granting the role
  there, though defining the role asks it of the tenant, or the label of a scope such a role is
  granted on refuses it. The constraints are asked about each such scope once, as
  `Config.ResourceOf` gives it, never of no resource alone, which a constraint that tells resources
  apart can answer with nothing, about what `Apply` granting the role there asks: the power to
  change grants there, and what the role gives, on a resource for that resource's type alone;
  without `Config.ResourceOf`, about each scope as stored where that is all of it, and otherwise of
  no resource, which then stands for every such scope, so a constraint answering false of no
  resource doesn't stop it there (see Host policy). A grant widens by what
  it gives through its principal, as checks read it: one to the tenant's members of a privileged
  role, or to the public of a role not marked `Public`, gives nothing, so widening the role asks
  nothing about it, and a redefinition that has it give something, as narrowing the role so that it
  is no longer privileged does, widens it, with what was added to the role while it gave nothing;
  where the role gives more to whomever it is granted, each grant giving anything through its
  principal widens, whatever its scope takes of what was added. A deny where the tenant's members
  hold a privileged role still stops widening it, as a catalog change that has the role no longer be
  privileged gives them what it gives then, and asks no one. Renaming a role or rewriting its
  description changes no grant, so needs only the power to define it, however its lists are stored:
  a role, deny or eligibility is the same in any order of its lists, and however often one names an
  entry, as one written around the package, by a seed or a restore, can hold them, so setting it
  again as it is read changes nothing. A role lists in `GrantableRoles` only roles that a
  `<type>:grant` it gives, on a type it is for, lets its holders grant, as roles that can be granted
  on that type, or it is refused as invalid: a listing none of them reaches would hand nothing on,
  and the actor's power to grant the role would go unchecked. One the role already lists so as it is
  stored, as once the role listed is narrowed or the catalog changes, it keeps, so renaming it still
  needs only the power to define it; one a change adds, or leaves handing nothing on by changing the
  role, is refused, and dropping one needs no power over the role listed. A listing, handing
  anything on or not, keeps the role listed from being deleted.
  `DeleteRole` removes one with its grants; `Roles` lists the built-in and custom roles a scope type
  takes. Custom roles follow the catalog: one gives only what the catalog still has, and is
  privileged when it gives what only privileged roles do, or changes access. A check, `Activate`
  and a change read only the custom roles they and the grants they read name, a change with those
  the roles it grants list, through others too, each once however many roles list it, at two
  lookups by its key and one read of its permissions, so the tenant's other roles cost them nothing;
  `CustomRoles`, `Roles`, `Grantable`, `SetRole` and `DeleteRole` read every one, which
  `rbac.MaxCustomRoles` bounds.
- **Labels on data:** a mandatory layer above every grant. A host declares label dimensions
  (`Config.Labels`), each `Ordered` (a level), `AllOf` (compartments) or `AnyOf` (releasable to
  these partners), and a resource carries its label (`Resource.Labels`), stored with it as its path
  is. A host declaring them supplies `Config.ResourceOf`, which gives the labels of the tenant, its
  groups and the other scopes changes reach: `New` refuses them without it, as invalid. A subject
  holds a dimension's values as permissions, `dimension:value`, which roles for the tenant alone
  give, so groups, eligibilities, expiry, conditions, denies on the tenant and history all apply to
  them. A custom role stored for another type too, as one defined before its dimension was declared
  can be, gives none of them, only the rest, so its grants count toward no exclusive dimension, and
  is as privileged as though it did.
  Every check decides them, and the powers to release, on the tenant with no attributes or label,
  whatever tenant it is passed, as a check of a labeled resource reads them,
  and a change hands one on only as the actor holds it there: a condition of theirs can't read the
  tenant's attributes, only `resource.type`, `.id` and `.tenant`, and any read of
  `resource.attributes`, a test of an attribute's presence, `in`, `size()`, a macro or a comparison
  included, fails, so a grant's gives nothing and a deny's applies; and a constraint is asked about
  that bare tenant, so one deciding them by the tenant's state reads it through its `q`. A check of
  a labeled resource, once a grant allows, and `Permissions` of one, once it would list anything
  the label decides, asks it once about each value the label asks for that the subject's grants
  give, of an `Ordered` dimension those as high as the label's, and nothing about the rest, as a
  change does for the label of each scope it checks; `Holding`, `Filter` and `Reachable`, which
  test any label, ask about every one, as do `SetRole` and `DeleteRole`, and `ChangeMembers` taking
  access away, which first decide whether the actor's values satisfy every label, and the approval
  `Config.Constraints` names.
  `Authorize`, `Explain`, `Permissions`, `Holders` and `Grantable` allow nothing else of a labeled
  resource unless what the subject holds satisfies the label, whatever its grants give, its values
  read with its grants, so none allows what no moment did, nor do
  `Apply`, `SetEligibility` and `DeleteEligibility` change its grants, nor `SetDeny` and
  `DeleteDeny` its denies, nor `SetRole` and `DeleteRole` the grants of a role on it, nor
  `ChangeMembers` the members of a labeled group, or of one holding access, named in or exempt
  from a deny, or that a member's activation was made through, on a labeled scope, nor `SetGroup`
  and `DeleteGroup` a labeled group or the groups of a labeled tenant, nor does `Activate` count
  an approval on a labeled scope by an approver whose own values, read with no request's
  attributes, don't satisfy its label, each reading the actor's or approver's values again under
  the change's locks, with the actor's grants there or the groups the approver approves by;
  `Explain` names the dimension that failed. A change checking the labels of many scopes, as one to
  the members of many groups, decides each of the actor's values once in each phase, when a label
  first asks for it, and evaluates a condition of the actor's that doesn't read the action once for
  all of them, each value still on a budget of its own, as a check of it is: `ChangeMembers` the
  groups' labels and those of the scopes its members gain or lose access on alike, by the values it
  read with its power over the members before its transaction, and under its locks by one read of
  that power and its power on every such scope, so the actor held all of them at one moment. Read
  again with its power on those scopes, each value was decided twice in each phase. For each it
  walks only the actor's grants giving values or powers to release, and of their roles only those,
  each role read once in each phase, as every check deciding a subject's values does, and `Holders`
  once for all the identities it lists, so other roles' grants, however many or large, cost a label
  nothing.
  `Filter` tests a `text[]` label column (`Columns.Labels`), looking each of a row's values up,
  byte for byte, in objects of the values the holding allows that the query builds once, so a row
  costs a few comparisons for each of its values however many the dimensions declare, in a custom
  plan or a generic one; the column needs no index, as the path's drives the query. `Reachable`
  returns the holding, and `Holding` with `Satisfies` checks data points in a feed without reading
  the database.
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
  a group, making a membership or a place end sooner, making a member a guest, suspending a
  membership, granting a grant again, setting an eligibility in force again to end no later, or
  redefining a custom role so that its grants give no value they couldn't, as renaming or narrowing
  it, is never refused. Where a dimension is exclusive, a tenant's changes run in turn, so two can't
  each give one value. The check reads every identity a change reaches, so a grant to the tenant's
  members or the public reads every member, and of the tenant's custom roles only which values those
  giving one give: a role giving none, however large, costs it nothing. A subject whose grants could give it two anyway, as
  after a catalog change, holds none of them, whatever the request, a constraint or a deny removes:
  checks and searches of its labels and of the values themselves refuse it, and it can't hand them
  on, but for those a role it holds lists in `GrantableRoles`, which it grants without holding, as
  any such role: the identity it grants one to is checked as in any change, so no one comes to hold
  two. Any other change reaching it is refused until a removal leaves it one; `Conflicts` lists
  them, reading the custom roles in the statement that reads their grants, so what it lists one
  moment held, under `WithTx` too. A change reaching many scopes decides which values its actor
  holds none of on each by reading each of the actor's roles once for all of them, and where no
  dimension is exclusive, not at all. A role giving two of them is refused. An `Ordered` dimension's
  higher values include the lower, so it isn't exclusive, and in an `AllOf` one a label naming two
  is one no one can read, as data that joins two parties is.
- **Conditions:** a grant can carry a CEL expression over the subject's, the resource's and the
  request's attributes (`Subject.Attributes`, `Resource.Attributes`, `rbac.WithRequest`), the time
  and the action. It gives its role only where the expression holds; one that fails is false. The
  time is the host's clock (`Config.Now`) in UTC, whatever zone it returns times in, and so is a
  `time.Time` the host passes: `string()` writes a time in its own zone, so `string(request.time)`
  compared with a literal decided by the zone each replica runs in. `string()` of a time the host
  passes in another zone, or of one computed from it, wrote it in that zone before, so a stored
  condition comparing that with text written at the zone's offset no longer holds; comparing
  times, and reading their parts, decide as before.
  `Config.Attributes` declares the attributes and their types, so a condition reading one
  misnamed, or as another type, is refused when stored, and one stored under other declarations
  fails where it no longer passes them. A condition building a message, as
  `google.protobuf.Struct{...}`, is refused, and one stored before fails: a grant's gives nothing
  and a deny's applies. What the host passes as attributes is converted into CEL's own values where
  a condition is read, the subject's and the request's once for each call, however many scopes a
  change checks, and the resource's once for each check, and conditions read nothing else: `nil`; a
  `bool`, a string, an int, a uint or a float of any size, of a type of the host's own too, as a
  named string, read by its kind; `time.Time`, in UTC, and `time.Duration`; bytes, as `[]byte` or an array
  of bytes; slices, arrays and pointers of these, a nil pointer read as null but one to what none
  reads, below; maps of these keyed by a bool, a
  string, an int or a uint, or by an interface holding one; JSON text (`json.RawMessage`, a nil
  one read as null, as `encoding/json` writes it) and `json.Number`, parsed; the protobuf `Struct`, `ListValue`, `Value`, `NullValue`, wrappers,
  `Timestamp` and `Duration`, and an `Any` packing one of them; and CEL's own scalar values.
  A kind's attributes, the subject's, the resource's or the request's, holding anything else,
  however deep, can't be read as a whole, as a policy engine fails input it can't read: every
  condition reading any of them fails, `has()` and `in` included, and so does one keying a map by
  them, comparing them or finding them in a list, building a list or a map holding them, as
  `[subject.attributes]`, whatever reads it, or reading the `subject`, the `resource` or the
  `request` holding them whole, as comparing it or `size()` does, rather than by a field's name,
  so a grant's gives nothing and a deny's applies, while the other kinds' are read. Built, a list
  holding them was decided by its size or another value it held, so `[subject.attributes] != []`
  held, and `[subject.attributes, 1] == [{}, 2]` failed for these but was false for a kind whose
  declared attribute was passed as another type; it fails for both. A map literal naming a key
  twice fails too, whatever it holds: CEL builds it holding the value named last, dropping the one
  before unread, so `{"a": subject.attributes, "a": 1}.a == 1` held where
  `{"a": 1, "a": subject.attributes}.a == 1` failed. Every kind's that
  can't be read are the same value, so a map hashed them as one: past what a check converts, below,
  `request.attributes in {subject.attributes: true}` held, and a deny guarded by its negation
  lifted. So do those holding a `ref.Val` of the host's
  own, though it says it is one of CEL's types, a list, map or optional of CEL's a host makes, a
  struct, a channel, a func, any other message, a map keyed by anything else, as a double or an
  array, and a slice, a pointer or a map of any of these, or an array holding one, holding none
  too, as an empty slice of structs or a nil pointer to one, read as `[]` or `null`, left a kind
  readable until it held one, a map holding two keys read as the same value, as `1`
  and `1u`, and so JSON text naming a member of an object twice, once unescaped, or an `Any`
  packing a message that sets a field twice, as a `Struct` with two entries of `role`: each is read
  as the last, where a host reading the first reads another. A `Struct` the host passes holds each
  key once, as a Go map does. So do invalid
  JSON, JSON text that isn't UTF-8 or escapes half a surrogate pair, which `encoding/json` reads as
  U+FFFD, a `json.Number` that isn't a number as JSON writes one, as `0x1p4` or `Inf`, a value
  holding itself, or one that does, and a value nested more than 10,000 deep, as JSON text can't
  be, along the longest path through them. A value reached twice is converted once, but one a
  resource's attributes share with the subject's or the request's, below. Reading the
  rest left each operator to tell what it read from what it couldn't, as `in`, `has()` and loops
  over a map's keys each found a key whose value no condition could read. A check converts no more
  than `2 × 80,000` of them, the subject's and the request's included however many checks share
  them, and a value the resource's share with them included again, as the resource's are converted
  apart, counted as reading them costs a condition, one for each value and a tenth of each string's,
  bytes', JSON number's, JSON text's or `Any`'s type URL's length, and half an `Any`'s packed bytes,
  but what building a value costs where that is more: 8 for each map, `Struct` or JSON object, 4
  for each list, `ListValue` or JSON array, each pointer, but to a message, and each other message,
  and 3 for each slice of bytes or JSON text, which a hook's copy keeps apart and converting parses;
  a map of values none reads, as structs, which reading copies whole, is refused unread at 2 for
  each entry, where one of 2,000 structs of 64 KiB, charged as much, took 7 ms, and each entry of
  another costs at least 1 for each 24 bytes its value holds in place, which reading it moves,
  where 19,000 empty maps of a type of 64 KiB, charged 8 each, took 1.4 GB and 270 ms making room
  for a value they didn't hold. That is about a map of
  50,000 short strings, nearly 16,000 maps of one entry each, nearly 40,000 timestamps or JSON texts
  of a byte, or 53,000 slices of a byte, and a
  unit costs about what reading one does, so a check spends no more converting than its conditions
  may reading, about 20 ms: each map charged one, as a number is, a
  check of a resource whose tags held 156,000
  empty maps took 108 ms, and each JSON text or slice of bytes charged as one value and a tenth of
  its length, a check took 80 ms to convert 79,000 texts of a byte, and a hook 76 ms to copy
  150,000 slices of a byte. Past that every condition reading an attribute fails, as it does where
  JSON text may cost more, by its brackets, braces, commas and colons. Converting stops
  10,000 deep, so what a kind nesting deeper is charged, and whether the kinds after it fit, can
  turn on the order a map's entries come in, failing closed, and nothing else turns on that order,
  nor on the order of the kinds, whether a hook can be given a copy included, below: a loop gives a
  map's keys in an order of their own. The subject's, the
  resource's and the request's attributes share what a check converts, so attributes a tenant's
  users write, as a resource's tags, can take every check of the resource past it, where a grant's
  condition reading an attribute gives nothing and a deny's applies, whoever asks: bound what users
  may store, or pass conditions only what they read. A call reads the subject's and the request's as
  its first check converted them: change none of them while it runs, as from a hook, as a check
  after the change can read them as they were, though never another value as one of them.
  Comparing a double that isn't finite fails, and no list or map a condition reads holds one:
  building a list or a map holding one
  fails, and an attribute holding one, however deep, is refused, as a declared double that isn't
  finite is, failing whatever reads it, and whatever reads its kind whole; and where no
  declarations cover the kind, none of its attributes can be read, as where they hold anything
  else: refused by name alone, a deny's
  `request.attributes.region == "eu" && request.attributes.risk > 0.5` lifted outside the EU for an
  infinite risk, where the same infinity as JSON text, `1e400`, applied it. Comparing reads the
  smaller value whole and the larger only as far, so a list holding
  one beside a long string was compared by the string: `[0.0 / 0.0, "<long>"] != [1, 2]` held, as
  did `request.attributes.scores != [1, 2]` where the request's scores held NaN beside one. Each
  condition runs within the most evaluating it can cost, which its literals and types bound: little
  for comparing what a request passes with literals, or with the ids, kinds, types and tenant a
  check passes or its action, which are no longer than `MaxID`, and all a condition may for reading
  the size of, or
  looping over, a list the request passes, or for looking up a key the request passes in a map,
  which hashes the key whole, as
  `{"dev": 1, "prod": 2}[resource.attributes.env]` does. A list literal costs 1 more for each
  element and a map literal 2 for each entry, each time it is built, and a step of a loop 1 more
  for each `&&`, `||` and `?:` it may evaluate, its macro's own among them, which CEL charges a
  constant or nothing. A loop over a map gives its keys in one order, whatever order the map's
  entries come in: bools, ints, uints, doubles, strings and then bytes, each by its value, strings
  and bytes by their bytes, so `{"b": 1, "a": 2}.map(k, k)` is `["a", "b"]`. It gave them in the
  order Go happened to range over the map, which changes from one evaluation to the next, so over
  a request's three scopes `request.attributes.scopes.map(k, k)[0] == "read"` held in 55 of 100
  identical checks, `Explain` disagreeing with the check before it in 51, and a deny's
  `request.attributes.scopes.filter(k, true)[0] == "admin"` lifted in 84, so a requester could ask
  until it lifted; and how far `all()` or `exists()` went before it stopped, and so what it cost,
  turned on it too. Sorting the keys costs, when the loop starts, 1 for each two keys each time
  their number halves to one, and each key what reading it does past 1, once, and a loop over a
  map holding more than one key of another type, as a literal keyed by lists can, fails.
  `contains` costs what reading both strings does, multiplied, and `startsWith` and `endsWith` what
  reading the shorter does, at least 1 however short or empty either is, and one costing more than a
  condition may fails before it runs: `contains` of one long string the request passes in another
  tries each place in it, which can take a third of a second. A comparison costs reading the
  smaller value, read once, in step with the other, and charged before it runs: measured again
  for each doubling of how far it read, again in search of a double that isn't finite and again
  for CEL's charge, comparing JSON nested 3,300 deep took twenty times what its cost implied.
  Reading a time in a zone costs 100, and 500 more where an attribute names the zone, at each read,
  whether or not the process has loaded it: charged only where it hadn't, the same check of the same
  request was refused the first time and allowed after, and decided by which zones each replica had
  loaded. Each process loads a zone, or finds a name names none, once, the zone a literal names when
  the condition is planned, and refuses, before loading anything, a name holding a byte no zone's
  name does, as `tzdata.zi`'s dot, and one with a part that is `Local` or `localtime` in any case,
  the zone the process runs in, as `posix/localtime`, which platforms keeping `posix` as a link to
  the zones' own directory loaded it by. Zones load from the platform's files, as `time` loads them,
  so a name one replica's files hold and another's don't, as `posix/` and `right/` names, which
  some platforms no longer install, decides by where the check runs, failing closed where it names
  none: name zones as the time zone database does. Loaded at each
  call, a check of conditions reading the hour in `tzdata.zi`, a file kept beside the zones, took a
  quarter of a second, and a request can name a new zone each time. The process keeps at most 1,024
  zones and names of none, dropping one at random past that, and a zone whose files change after
  it loaded it reads as it was until it is dropped; but where reading the files failed, as once
  the process ran out of file descriptors, it keeps nothing, and a condition naming the zone
  fails until they can be read, where kept it failed until the process dropped it. Cost is
  bounded per check too, for each scope on its path, and the conditions a check reads together
  are bounded where they are stored: an identity's grants' on a scope, those of a scope's grants
  to groups, the tenant's members and the public, each the tenant's and those from each source
  the host owns apart, a
  scope's denies',
  and the requirements of groups' eligibilities for a role on a scope. Each holds hundreds of
  comparisons with literals, a hundred of an attribute with the subject's id, or three of the
  longest conditions that read a list, look up a key the request passes or loop, and a change
  adding a condition past one is refused as invalid. So a check evaluates every condition it
  reads, and a grant made beside another, as by someone who can't revoke it, never changes what
  that one decides. A change adding no condition isn't refused, so what was stored past a bound
  before there were bounds can be rewritten in place, as by a restore over the rows still stored,
  though not restored where they are gone, and a check may not reach all of it: it evaluates the
  cheapest first within its budget. An upgrade of CEL, or of this package where it bounds a shape
  more, can leave conditions stored past a bound in the same way: each process bounds a stored
  condition again by what it and the CEL it is built with make of it, so another version can bound
  one more, and the package's tests pin the bounds of conditions of common shapes, so that one an
  upgrade moves fails them. A condition holding a literal or a logical operator is bounded a few
  units higher than before they were charged so, and one rebuilding a literal of hundreds at each
  step of a loop at all a condition may cost, past which it fails: a grant's gives nothing and a
  deny's applies. A step of `all`, `exists`, `exists_one`, `filter` or a `map` that filters costs
  1 more for the operator its macro evaluates, so one looping over a list the request passes, which
  cost nearly all a condition may, can now cost more, and fails the same way. One reading a time in
  a zone an attribute names is bounded 500 higher than before loading it was charged, so a scope's
  conditions that read many may be past a bound as an upgrade leaves them, and costs those 500 at
  each read, so one reading more than about sixteen in a loop, which held once the process had
  loaded them, fails. A loop over a map costs sorting its keys, so one over 500 short keys, which
  cost about half what a condition may, now costs about two thirds, and one over more than about
  700 fails the same way, or over more than about 580 keys of 36 bytes, as ids, each costing its
  bytes once more, as does one over a map literal holding more than one key of another
  type, as lists; a scope's conditions looping over map literals are bounded a little higher too,
  so they may be past a bound as an upgrade leaves them. Adding
  to `request.time`, or converting it, was bounded at all a condition
  may cost and is now bounded as the timestamp it is, a few units. CEL now refuses ordering numbers
  of different types, as `[1, 2].exists(i, i < 2u)`, which it accepted before once it had checked a
  loop, so a condition stored so no longer compiles: a grant's gives nothing and a deny's applies;
  and where `Config.Attributes` declares a number, so does one ordering it against a number of
  another type past a loop, as `[1].all(v, true) && request.attributes.n < 2u` for an int `n`, though
  it compiles where none is declared. To find those stored, list each condition stored, `SELECT
  condition FROM rbac_grants UNION SELECT condition FROM rbac_denies UNION SELECT requires FROM
  rbac_eligibilities`, and compile each but the empty one with CEL's `cel.NewEnv` declaring
  `subject`, `resource` and `request` as `cel.MapType(cel.StringType, cel.DynType)` and `action` as
  `cel.StringType`, as the package compiles them: one whose `Compile` gives issues no longer
  compiles. Storing one again is refused with what CEL found (`rbac.ErrInvalid`), one failing
  against the declarations too, which compiling so doesn't find. `AsOf` compiles those history
  holds too, `SELECT after->>'condition' FROM rbac_history WHERE entity IN ('grant', 'deny') UNION
  SELECT after->>'requires' FROM rbac_history WHERE entity = 'eligibility'`, which can't be stored
  again, so a check of a time one of them was stored decides it as failing. A condition naming a
  variable from the root where a loop's variable of the same name hides it, as `.request` in
  `l.all(request, ...)`, read a key indexing it outside the loop, so one naming a loop's variable
  of another name, as `k` in `.request.attributes.m.exists(k, .request.attributes.m[k] > 0)`,
  failed, and one naming the loop's variable that hides it, as `request.attributes.k` in
  `l.all(request, .request.attributes.m[request.attributes.k] > 0)`, read the variable instead: each
  is now read in the loop. Each field or key such a variable is read by costs 1, as it does of any
  other, and so does what computing such a key evaluates, which CEL charged nothing for, though its
  bound counted it, so one whose key searches or loops over what the request passes can now cost
  past what a condition may, and fails the same way.
  Attributes holding JSON text or
  a packed message that sets a key twice, JSON text that isn't UTF-8 or escapes half a surrogate
  pair, or a `json.Number` JSON doesn't write, were read and now can't be, failing every condition
  reading their kind, and so are ones holding an empty or nil slice, map or pointer of values no
  condition reads, as structs, channels, funcs or messages of other types, read as `[]`, `{}` or
  `null` where one holding such a value couldn't be read; and a map's values no condition reads,
  as a host's own array saying it is a double, or nesting past 10,000 deep, each cost at least 1
  for each 24 bytes they hold in place, so the kinds converted after them can be past what a check
  converts. Attributes
  holding maps, lists, pointers, messages, slices of bytes or JSON text are charged what building
  them costs, so ones a check converted before can be past what it converts now, as 80,000 empty
  maps, 79,000 JSON texts of a byte or 150,000 slices of a byte are, or lists and JSON texts that
  are slices of one array, one with room to grow, now each converted, as a hook's copy copies each,
  failing every condition reading an attribute, and past what a hook's copy holds, so a
  call asking a constraint about them, or `ValidateGrant` about an actor holding them, is refused
  whatever grants it, and so can ones holding structs that hold a map, a slice, a pointer or an
  interface, which a hook's copy sets whole and is now charged their bytes, their padding too, as
  it charged a struct holding none, or messages of the host's own types, which a copy makes whole
  and is now charged what the messages their types make hold in place, set or not, as 1 for each
  24 bytes, or maps keyed by
  arrays or structs, or by interfaces holding them, whose keys it is
  now charged the bytes of, and of the strings they hold and what their interfaces hold, as hashing
  them reads; and so are ones nesting past 20,000 deep, of which a hook was given what lay deeper as
  its zero value, and ones holding themselves that reach 20,000 maps, lists, pointers, structs,
  arrays and messages, counting each time one is reached, however shallow, which were copied
  whole, and ones holding a lock, an unsafe pointer or a struct's unexported field holding a
  pointer, a slice, a map or an interface, which a hook was given copied whole, sharing what the
  field held with the host; and a condition building a list or a map holding attributes no condition can
  read, or reading the `subject`, the `resource` or the `request` holding them whole, as one
  deciding a label value or a power to release reads the `resource`, was decided without them and
  now fails. So does one building a list or a map holding a double that isn't finite, as
  `has({"k": 0.0 / 0.0}.k)`, or a map naming a key twice, which keys a condition computes can do
  only as it runs, as `{subject.id: 1, "admin": 2}` does for the subject `admin`; and where no
  declarations cover a kind, so does every condition reading its attributes where one holds such a
  double, however deep: it read the others, and that one too, as `has()` and `size()` did. Going
  back to an earlier release of this package does the same where that release bounds a shape more,
  so while replicas of two releases run side by side, those
  bounding a shape more may refuse changes adding a condition to a scope the others filled. To
  hand a permission on, the actor holds it unconditionally or under the same condition, one that
  doesn't read the subject: that one decides for each holder, so the actor's holding says nothing
  of another's.
- **Deny policies:** `SetDeny` puts a deny on a scope: under it, it removes permissions
  (`type:verb`, or `type:*` for a type's every one) from the principals it names, those it exempts
  aside, whatever their grants give. It names and exempts principals a grant could name, so not
  one of a kind the host doesn't declare. It exempts identities and groups, or from a deny naming
  the public the tenant's members, to bind only those who aren't; never the public, which would
  exempt everyone, nor one it names. A conditional one denies where its condition holds or can't
  be evaluated. Setting one needs `rbac.DenyPermission(type)` there, which no deny removes, so
  whoever holds it on a scope above can always lift a deny set below. `Filter`, `Reachable` and
  `Holders` honor denies, `Holders` marking whom a conditional one binds rather than leaving them
  out (see Why).
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
  those made to their ends, or to their holders leaving its group: on a labeled scope,
  `ChangeMembers` ends them so only for an actor holding what the label asks for, as revoking them
  there needs, and on a frozen one not at all; on any scope, `DeleteGroup` refuses a group they rest
  on. `Activate` holds the places in groups an activation rests on until it commits, and each of
  these reads the activations once it holds the places it ends, so one made while it waits is
  checked as one made before: `ChangeMembers` is tried again (`rbac.ErrConflict`), and
  `DeleteGroup` refuses it. On a labeled scope, only an approver holding what its label asks for
  approves.
- **Host policy:** `Config.ValidateGrant` is asked about every grant with the role, the principal,
  the actor and how it is made, so the host decides who may hold what: members only, no
  privileged roles for service accounts or guests. `Config.Constraints` remove permissions above
  anything a tenant grants or denies, seeing copies of the subject and the resource, such as
  freezing changes under a container. Each constraint is given copies of its own, made the first
  time a call asks it about each and given it again whenever the call asks about the same, as
  `Permissions` does for each permission and a check of a labeled resource for each value its label
  asks for, so one writing to its copy reads its write later in the call, and nothing else does;
  copied for each ask, `Permissions` of 300 permissions on a resource of 20,000 tags took a second.
  `ValidateGrant` is given its copy of the actor's attributes once for a call too. A copy holds no
  more than a check converts, counted alike, and nothing nesting past 20,000 deep, twice what a
  condition reads, along any path, wherever a value reached twice is reached first, nor a value
  holding itself, as a graph of objects with links back can, that reaches 20,000 maps, lists,
  pointers, structs, arrays and messages, counting each time it reaches one, however shallow: how
  deep a path around the cycle nests turns on where the copy enters it, which the order a map's
  entries come in picks, so two links each holding the other, beside a chain of 9,998 links to one
  of them, were copied on one call and refused on the next. Nor does it hold what can't be copied
  as a value: a lock, as a mutex, a `WaitGroup`, an atomic value or a protobuf message held by
  value holds, an unsafe pointer, as a `reflect.Value` holds, or a struct's unexported field, which
  a copy can't set, holding a pointer, a slice, a map or an interface, as another package's types
  keep their state in; a host's type that is its own reflection by a generated message's it embeds
  is given holding the reflection of a copy of the message. Where the attributes hold more, nest
  deeper, hold themselves so or hold what can't be copied, the hook can't be asked, rather than be
  given part of them,
  and the call is refused as any other, a `DeniedError` of the permission on the resource
  asked about, or the tenant, whose `Reason` names the hook and whose message doesn't: a tenant's
  users can write what takes attributes past it, as a resource's tags, and the message named the
  constraint. What one removes from an actor the actor can't hand on, but for a
  role a role it holds lists in `GrantableRoles`, which it grants without holding. A freeze stops
  every change an actor makes to grants under it, and every change taking access away there: one
  removing `<type>:grant` from the actor, or a deny on the path doing so, stops `Apply` granting and
  revoking there, and so it stops any change taking access away there, whatever the actor's grants,
  as `DeleteRole` deleting a role granted there, `ChangeMembers` removing a member of a group
  holding access there, making its place end sooner, ending an activation made there through the
  group, or adding a member to a group a deny there names, and `DeleteGroup` deleting a group with
  grants or eligibilities in force on its own scope, which it reads, as `ChangeMembers` reads a
  scope it takes access away on, as `Config.ResourceOf` gives it, so a condition reading the
  group's attributes reads what the host passes `Apply` there. Each is stopped by what it ends
  there, not by what the members hold after it: a member leaving a group ends there what the group
  and those it is in give it, a grant, eligibility, approval or exemption, so one that another group
  or a grant of its own gives the same is stopped too, as `Apply` revoking a grant held twice is,
  and so is one ending only an eligibility, as `DeleteEligibility` there is; but a place that ends
  while another, from another source, keeps the member in its group as long ends nothing there.
  `SetRole` and `DeleteRole` decide a constraint on changing grants, and a deny on the tenant, once
  for every scope of a type the role's grants can be on, as of no resource and on the tenant, where a
  condition reading the resource can't be evaluated and so denies: a role's grants span scopes no one
  reads, so they are stopped wherever either may stop `Apply` on some scope of the type, not only on
  those it would. So a constraint asked of no resource (`ConstraintInput.Resource` nil) must answer
  true if it removes the permission on any scope of the type, as `ConstraintInput` says. One that
  answers false there, as one written for resources alone and guarded against a nil `Resource`
  does, isn't asked about the scopes themselves by `DeleteRole` or by `SetRole` narrowing a role,
  nor by `ChangeMembers` and `DeleteGroup` taking access away unless a label, a deny or another
  constraint has them read the scope, so as a freeze it doesn't stop them, though it stops `Apply`
  revoking there; nor, without `Config.ResourceOf`, by `SetRole` widening a role granted on a scope
  it can't read whole, so it doesn't stop it handing on there what it removes. With it, `SetRole`
  asks about each scope a widening gives more on as `Apply` granting the role there asks, whatever
  the constraints answer of no resource.
  The host's own writes (`Import`, `DeleteGrants`, `SetMemberships`, `ImportGroups`,
  `ImportMembers`, `DeleteMembers`, `DeleteGroups` and the host's deletes) make none of the checks
  an actor's change makes, so a freeze stops none of them, `ImportGroups` taking a tenant's group
  over too, which removes the members the tenant put there and cuts short what they activated
  through it: the host freezes those itself. The host is
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
  its exemptions from denies and its place among approvers too, but for a deny or an eligibility
  naming it that commits once it has found those, which it leaves as if set after it: `SetDeny` and
  `SetEligibility` take no lock of the identities they name, and taking it out of one meanwhile
  could deadlock with another removal. Removing it again takes it out. `DeletePrincipalEverywhere`
  removes a deleted identity from every tenant.
- **Groups:** a group is its tenant's (`SetGroup`, `ImportGroups`), and `group:<id>` names it only
  there. Its members are identities that are members or guests of the tenant, and other groups of
  the tenant, at most `rbac.MaxGroupDepth` deep (`ImportMembers`), each from a source, perhaps
  until a time. Every check, list and deny reads an identity's groups, through those they are in,
  as they are stored now: `Authorize` and `Filter` in the same statement as its grants and denies,
  and `Explain`, `Reachable` and `Holders` in one snapshot of the database, but under `WithTx` at
  READ COMMITTED, where each statement reads its own.
  A suspended identity holds only what the public does, and stays bound by a deny naming its
  groups or the tenant's members, though no group of its exempts it from one: suspending it lifts
  nothing. One whose membership has ended is in none of its groups, though `DeleteExpired` hasn't
  removed its places yet: `Members` and `GroupsOf` list none of them, `ChangeMembers` removing it
  from one takes nothing away, so no freeze, label or deny refuses that, though making its place
  there end sooner adds an identity that isn't a member, which is refused, as `ImportMembers`
  refuses importing its place again, once it has asked `ValidateGrant` about what the place gives,
  as for any identity that isn't a member, `DeleteGroup` counts none as a member from a source the
  host owns, and a change counts none in what the host was asked about, which it reads again under
  its locks. Read as stored, each such place was one a removal took away, and a member the host
  keeps, until `DeleteExpired` ran; and a change asking the host about its group meanwhile was tried
  again once `DeleteExpired` removed it. When the host takes a group over (`ImportGroups` from one
  of `Config.Sources`), the members a tenant put in it, from no source of the host's, leave it.
- **Changing members is granting:** a group's members hold what it and the groups it is in hold,
  so `ChangeMembers`, with `rbac.GroupMembers` on the group and its label, checks a change to its members as the
  changes to access it makes, each as `Apply` or `SetDeny` checks one on its scope. An added member
  gains the grants and eligibilities of the group and the groups it is in, those the same change
  nests it in too, which the actor must be able to grant it, until its place ends, and an
  eligibility for good, and `ValidateGrant` is asked about each as the member's
  (`rbac.ViaMembership`); it approves what the group approves, which the actor must be able to set;
  and it is exempt from the denies the group is exempt from, as a removed member is from those
  naming it, which the actor must be able to set. A removed member loses the rest, and the
  activations made through the group, and an added one is bound by the denies naming the group,
  which the actor needn't be able to grant, but which the label of each scope, and a freeze there,
  refuse it, as each refuses a revoke there. A place made to end sooner gains nothing: it is a
  removal then, checked as one now; nor does one whose note alone changes. So whoever manages a
  group that holds, approves and is in no deny, and that no member activated through, changes its
  members freely, and one holding a role only if they could grant that role themselves. Whether
  the actor may make a grant is decided once for each end, however many members gain it, but the
  host is asked about each as each member's, so the members one `ChangeMembers` adds gain at most
  `rbac.MaxBindings` grants and eligibilities in all, each member's counted apart, but no more
  than one place alone gains, whatever its group and those it is in hold. A member is its
  principal, however many groups, or places in one, the change gives it: what they reach counts,
  and the host is asked about it, once for each end its places give it, so a group two of them are
  in counts once, as does a group it is placed in from two sources until one end; but a member
  joining several groups that give more than `rbac.MaxBindings` together, and more than any one of
  them alone, joins them in more than one change.
  `ImportMembers`, the host's own write, which no actor's access decides, has no such bound: it asks
  `ValidateGrant` once for each member and each grant or eligibility the member gains, so its cost
  grows with how many they gain. The rest is the groups', read once however many of their members
  change, and what a group many of them are in reaches, once for all of them, and grows with what
  the groups hold, approve and are named or exempt in, so grant a group on a container rather than
  on each resource in it: with labels or constraints declared, or a deny binding the actor that
  removes a power to change grants, a removal reads what its members lose. It asks the constraints
  once about changing grants on each type of scope they lose access on, of no resource, and
  `Config.ResourceOf` about each such scope only where the actor's label values don't satisfy every
  label, a constraint answered that it may stop the actor on some scope of the type, or a deny
  binding the actor removes `<type>:grant` or `<type>:*`: then the constraints again about each, and
  the denies on all their paths in one read. Which types such a deny names, wherever it is, it reads
  before its transaction and again under its locks, in the read of its power over the members, so
  it held that power and escaped such a deny at one moment, of the denies naming the actor, its
  groups, the tenant's members or the public, through an index of those alone that remove a power
  to change grants, so the others naming them, as of root on each of thousands of resources, cost
  it nothing; `DeleteGroup` reads them so, with its power to manage groups, for the grants on the
  group it revokes.
  `Config.ResourceOf` gives the package the tenant, which `SetGroup` and `DeleteGroup` check
  `rbac.ManageGroups` on, and the groups, which `ChangeMembers` checks `rbac.GroupMembers` on and
  `SetGroup` and `DeleteGroup` the label of, each with its constraints and label, and the
  containers, label and attributes of the scopes a group's access is on, and of a group whose own
  scope `DeleteGroup` revokes grants on where a constraint, a deny binding the actor or its label
  may stop that; a host declaring labels needs it, and `New` refuses them without it as invalid; one
  without it declares resource attributes as none, and for access below the tenant, no containers:
  otherwise a change checked on such a scope as stored is refused, as `DeleteGroup` is once it finds
  anything granted on the group's own. For a scope the host no longer has, as a resource deleted without `DeleteScopes`, it
  returns `rbac.ErrNotFound`, or an error wrapping it: a change that only takes access away there,
  as a
  member leaving a group with access on it or the group itself, or joining one a deny there names, a
  place in the group made to end sooner, `DeleteGroup`, or `DeleteRole` deleting, or `SetRole`
  redefining so that no grant of it there widens, nor would once the catalog has it no longer be
  privileged or the host declares the kind it is to, nor may the holders of a role listing it
  granted there hand on more, a role granted on it, reads it as stored, unlabeled and under no
  container, which a freeze on its type or the tenant still stops, and any other change fails with
  the error.
- **Privileged roles:** a role the catalog marks `Privileged`, or one that changes access, is
  privileged: it is never granted to the tenant's members, and gives nothing through them, as
  after a catalog change. Their grants of it give what it gives once it no longer is: `SetRole`
  checks a redefinition doing so as widening them, but a catalog change doing so is the host's, and
  asks nothing.
- **Public access:** the zero `Subject` is anonymous and holds only what is granted to the public.
  Only a role marked `Public` can be granted to the public, and a grant to the public gives
  nothing once its role no longer is. `Grants`, `Eligibilities`, `Memberships`, `MembershipsOf` and
  `GroupsOf` take its zero principal, as a constraint may ask about it, and list nothing of it.
- **Broad grants:** a grant to a tenant's members (`rbac.TenantMembers`) or the public never gives
  a privileged role, nor any permission that changes access, so changing access always takes a
  named identity or group.

## Why

`Explain` names the grants that allow, or the deny, the constraint or the label's dimension that
denied, or for a value of an exclusive dimension the subject holds none of, that dimension;
`Permissions` lists what a subject may do; `Holders` lists who may, for an access review: each
identity, through its own grants and its groups', and the tenant's members and the public as one
holder each, marking those that hold only under a condition or that a deny or constraint may bind.
It evaluates no condition, so it lists too many rather than too few: every conditional grant and
deny is marked unevaluated, so those marked can include one a condition reading only the resource
always refuses, or always allows, and a deny leaves out whom it binds only where it has no
condition. That holds of a labeled resource's holders' label values too: it lists the same
whatever their conditions come to, so it evaluates none of them, where evaluating each holder's
and setting what they came to aside, a value granted to a group of 1,000 under a costly condition
took it a second, and granted under none, 33 ms. A `DeniedError`'s message names only the
permission, so an error shown to a user shows no policy; its fields say why. Every refusal is one,
a hook that can't be given its copy too.

## History

Every change to the package's tables is recorded in `rbac_history`: the row as it was and as it
became, when, and the database role that wrote it; and each transaction that changes them records
when it commits, which `History` returns with each of its records (`Record.CommittedAt`) rather
than as a record of its own, and each record holds the cluster that wrote it (`Record.Cluster`, its
`system_identifier`), within which a commit record dates it. A change through the package records
its actor and the call that made it (`Record.How`), and what the host attaches with
`rbac.WithAudit`: on whose behalf it was made, the request and the reason. An expiry `DeleteExpired` removes is recorded as
one, made by no one, and so is each time it records in `rbac_expired` that every check and change
decides no earlier than, as the entity `expired`, in no tenant, keyed by its row's id, as two rows
can hold one time (see Expiry). Triggers write it, so a write that bypasses the package is recorded
too, as no one's. That context is what the session that wrote it says; the database role is what the database
knows. The tables bound what they hold as the package bounds what it writes, but for the ids in
a deny's principals and exemptions and an eligibility's approvers, which they count to
`rbac.MaxID` characters rather than bytes, so a write around the package can store those at up
to four times the bytes the package writes; and a write whose row is more than 1 MiB as jsonb,
or whose context is more than 1 MiB, fails rather than record what `History` couldn't
return. A row written before history was installed, as by a host that applied the first migrations
on their own, is recorded by migrating as it found it, its `baseline`, dated when it was created, or
a role when it last changed. Nothing updates or truncates history, only `PruneHistory` deletes from
it, and the package's tables can be deleted from but not truncated. `History` reads it in the
order of the transactions that wrote it, by the id each takes at its first write, to export it to
storage of the host's own: a transaction that commits after one that took its id later is read
before it all the same, never skipped. That is the order of transactions, not of each row's
changes: one that took its id first and changed a row after another committed a change to it is
read before that one, though its change came after. So a consumer replaying an export applies each
row's versions in the order of their `Record.ID`, in which they were written while history's id
sequence caches one, as `AsOf` reads them and requires, not in the order read, or it ends with a
version the row no longer held. A record can be read
twice, so dedupe on `Record.ID` and `RecordedAt`: a restore can give another record the ID of one
it lost. One call reads at most `rbac.MaxHistory`
records, and past the first, at most `rbac.MaxHistoryBytes` of their rows' JSON and their text, so a
read of fewer than its limit doesn't mean history holds no more: read until one returns none.
History written before `0013_bounded_rows` counted no bytes, so a read measures each such record by
writing out its rows, and reads at most 100 of them. Any transaction still running in the database
cluster, in any of its databases, that has written or otherwise taken a transaction id holds
`History`, and `Export` with it, back until it ends.
`idle_in_transaction_session_timeout`, and
from PostgreSQL 17 on `transaction_timeout`, end one a session leaves open by mistake, but every
session may set both for itself, whatever the role's or the server's defaults, so they bound only
an accident: a session of a role that may be hostile, as the application's, turns them off and
holds every export back for as long as it stays open. Watch for one: `pg_stat_activity`, read as a
role with `pg_read_all_stats`, as `pg_monitor`'s members have it, lists every session's
`backend_xid`, whose `age()` grows while it holds `History` back, and `xact_start`; end one held
too long with `pg_terminate_backend(pid)` as a role with `pg_signal_backend`, which can end any
session but a superuser's, and find out why it was held. A prepared transaction outlives its
session, and no timeout or termination ends it: it holds `History` back until it is committed or
rolled back, so keep `max_prepared_transactions` at 0, the default, or watch `pg_prepared_xacts`
and resolve any left there. A time a record holds as PostgreSQL's infinity, which the tables
refuse but an older record can hold, reads as an instant just past either end of PostgreSQL's range,
as `Record` says, so `History` reads on past it. `History` reads the primary, and fails on a
replica. A generation (`Cursor.Generation`) names the cluster, and the database and schema history
is in, so no two installations in a cluster share one. A failover or a recovery to a point in time
starts a new one, and a restore that starts none, as from a disk snapshot, loses what came after it:
either can number again what the last one numbered past what it kept. A `pg_upgrade` starts a new
one too, as it gives the cluster a new identifier and starts its timeline at 1, though it loses
nothing: export to the end before it, and keep the last checkpoint, as every cursor from before it
is then refused, and the whole of history is exported again from `Genesis` under a new chain, which
an audit compares with the last export up to that checkpoint. `History` refuses a cursor
from another generation, whose last record the database no longer holds, or after which a prune
since its export began deleted records, as below, and history is exported again from the start, kept
apart from the last export: an export from it would read on past what is gone. A restore that keeps
a cursor's last record but loses what came after it, as one from a disk snapshot taken since that
cursor was read, leaves nothing the database can tell from recovering from a crash, which loses
nothing that committed, so its export would read on: restore by recovering to a point in time, which
starts a new generation, or export each generation from the start again after a restore. Move
history with physical backups and replicas; a logical dump restored into another cluster numbers its
transactions anew. `AsOf` still dates a restored change by its own commit record, as a commit record
dates only changes of its own cluster, and a restored change whose commit record is gone counts from
its own date; a transaction this cluster gives a restored change's txid is another, which commits,
and whose changes `AsOf` counts apart from the restored one's. `pg_upgrade` gives the cluster a new
identifier and keeps its transaction ids, so `AsOf` answers as before. Never bring back rows of a
timeline a recovery to a point in time left behind: they keep the cluster's identifier while the new
timeline numbers their transactions again, so `AsOf` would date such a change by another
transaction's commit.

A change refused, as `ErrDenied` or `ErrInvalid`, writes nothing, so history doesn't record it:
`Config.OnRefused` is told of each, with its actor, the call and the host's audit, to record the
failed attempt on a connection of the host's own, which keeps it when a host transaction the
change was made in (`WithTx`) rolls back.

`Export(ctx, from, limit, signer)` reads as `History` does and chains what it reads onto `from`,
a `Checkpoint`: a SHA-256 hash chain over every record of the generation in order, signed by the
host's `crypto.Signer`, such as a key in a key management service. `from` is the zero `Checkpoint`,
or one `Export` returned that the signer's key verifies: one whose cursor was moved ahead would skip
the records between with a chain that verifies. To change keys, `Sign` the latest checkpoint, once
the old key verifies it, with the new one, and go on from that. Keep the records and each
checkpoint where they can't be rewritten, as write-once storage. `VerifyChain` then shows that the
records between two checkpoints are those history held, none dropped, changed or reordered, which
a database's superuser couldn't forge past the last checkpoint stored: `History` refuses a cursor
after which a prune since its export began, or any delete through history's triggers, removed
records, so no export reads on past them. A checkpoint vouches for
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
an access review of a past date. A change counts from when its transaction committed, as no other
session sees it before then, by the record history keeps of it, or from its own date
(`Record.EffectiveAt`) where that is later: a revoke a host's transaction holds open, or whose
`Config.OnChange` takes a while, reads as of a time before it committed as the grant every check
then read, and a grant as not yet made. A change's own date is when the statement that made it
began, or its transaction, where that began later, as each one a procedure or a `DO` block starts
as it commits does; an expiry's when it expired; and none is before its row's change before it, as
the writer's snapshot holds it: at READ COMMITTED, as the package changes the tables, a statement
that waited for another's lock on the row reads the change it waited for, but at REPEATABLE READ or
SERIALIZABLE its transaction's snapshot is older, and it is dated before that change. Write around
the package at READ COMMITTED. A change of a transaction that committed before
`0027_commit_dates`, which records no commit, counts from its own date, as it did: from before the
transaction committed, and so a revoke held open counts from before a moment when checks still
allowed what it revoked. The transaction reading counts none of its own changes, which haven't
committed.

A transaction's commit record is written as it commits, by a trigger deferred to the commit, after
every change it made, and so what a time reads is final once every transaction whose commit record
is dated by then is one other sessions see: a commit counted by a time, but not yet seen, is one
still running the rest of its commit; one waiting for synchronous replication, as long as
`synchronous_standby_names` and the session's `synchronous_commit` have it wait, which a session can
set to `remote_apply` to wait for a standby to replay it; or one prepared for two-phase commit,
whose deferred triggers fire, and whose commit is recorded, as it is prepared, not committed. The
rest of a commit is the host's own deferred triggers and constraints of statements after its last
change to the package's tables, and what they wait for, as a deferred foreign key's check waits for
a row another session has locked; the session's temporary tables made `ON COMMIT DROP` or `ON COMMIT
DELETE ROWS`, which it drops or empties, about half a millisecond each at the default `temp_buffers`,
so a session with thousands holds its commit back for a second or so; and no lock it waits for longer
than 100 ms, where the session's `lock_timeout` is longer, as another session that holds one of those
temporary tables would have it wait, or past which it fails with SQLSTATE 55P03. Emptying an `ON
COMMIT DELETE ROWS` table scans the session's temporary buffers, so at a large `temp_buffers` it
costs more: at `temp_buffers = 4GB`, 2,000 such tables held a commit about 5.4 s past its commit
record, which `lock_timeout` doesn't bound, as it isn't a lock wait. A session that sets a large
`temp_buffers` and makes many such tables holds its own commit back accordingly; set `temp_buffers`
no larger than the session's temporary data needs. The rest of a commit also writes the
notifications the transaction queued, with `NOTIFY` or `pg_notify`, to PostgreSQL's notification
queue, which no SQL can see beforehand: about 1.6 ms a MB on a test server, 260 ms for 160 MB, and
some 13 s at the default queue of 8 GB, which `lock_timeout` doesn't bound either. Any role may
`NOTIFY`, which takes no privilege, so revoking `EXECUTE` on `pg_notify` from `PUBLIC` bounds
nothing. From PostgreSQL 17 on, `max_notify_queue_pages`, set as the server starts, bounds it: a
commit whose notifications overflow the queue fails with SQLSTATE 54000, its changes with it, rather
than being held, so 1,024 pages, 8 MB, hold one about 13 ms at most. But the queue holds every
notification some listener in the cluster has yet to read, and any role may `LISTEN`, so a small
one fills while a listener lags, as one in a long transaction does, and every commit that notifies
then fails until that listener catches up or ends: where the host's own transactions notify, size
it for how far its listeners fall behind, and retry such a commit once the queue drains, or keep
the default and watch `pg_notification_queue_usage()`. And the rest of a commit runs, after the
deferred triggers, each loaded extension's pre-commit callbacks: postgres_fdw commits there every
remote transaction the transaction opened, as any read or write of a foreign table opens one, and a
remote `COMMIT` waits for what the remote server has it wait for, as a remote deferred foreign key's
check waits for a row another session holds there, which `lock_timeout`, the local session's,
doesn't bound: in a test, a commit 1.5 s past its record, for as long as the remote lock was held. A
role with `USAGE` on a postgres_fdw server and a user mapping, or a privilege on a foreign table
and a mapping another made, can do this, and one with `USAGE` on the wrapper can make a server of
its own. So can one with none of these that may read or write a view, or call a function that runs
as its owner, that reaches a foreign table, through the owner's mapping; and `pg_read_all_data` is
a privilege on every foreign table. The commit record doesn't refuse a
transaction that used a foreign connection, which PostgreSQL 18's `postgres_fdw_get_connections()`
could tell it: no check of postgres_fdw's sees another extension's callbacks, as another
foreign-data wrapper's that commits its own remote transactions, nor a connection a deferred
trigger of the host's opens after the commit record, so the roles below give the application's role
none of these. `pg_stat_activity` lists a session
in its commit, with `COMMIT` as its query, or waiting on `SyncRep`, and `pg_prepared_xacts` a
prepared transaction until it is committed or rolled back; keep `max_prepared_transactions` at 0,
the default, so none is. Any session can fire a transaction's deferred triggers before it commits,
with `SET CONSTRAINTS ... IMMEDIATE`, which takes no privilege, and then hold the transaction open:
the trigger, so fired, defers itself again, and records the commit anew as the transaction commits,
which `AsOf` counts it from, as its latest. It refuses a transaction that declares a cursor `WITH
HOLD`, which committing runs to its end, also one a procedure or a `DO` block declares in a
transaction after it committed, and a session that has an enabled deferrable trigger on a temporary
table, which fires as it commits: either would run a session's own code after the commit record was
written. In a procedure or a `DO` block, it refuses too a transaction that has a cursor `WITH HOLD`
open that the block declared in an earlier transaction, whose commit ran it, as a cursor's creation
time is the block's, and nothing tells it from one declared in this transaction: declare such a
cursor before the block, in a transaction of its own, and fetch from it in the block by its name, or
close it before a transaction that changes the package's tables commits. A query string of several
statements, as the simple protocol sends one, as pgx's `Exec` in its simple mode or `psql -c` does,
counts as one such block, as each of its statements, and each of its transactions, began when it
did: a transaction of it that changes the package's tables is refused after one of it that declared
a cursor `WITH HOLD` and committed, which ran it, so declare the cursor in a query string of its
own. A `FOR` loop over a query,
which PL/pgSQL runs to its end as each `COMMIT` in it begins, is not refused. The check of a
temporary table's deferrable trigger reads the catalog as the commit record is written, so it is a
best-effort defense that holds only where a hostile session can't make temporary objects: the roles
below revoke `TEMPORARY` on the database from `PUBLIC` and grant it to none of them, as no call of
the package's makes a temporary object, `AsOf`'s included, so none of them makes any, and against
them the defense holds. So the application's role can hold a change's commit past its commit record
by what runs after it as the transaction commits, which includes the host's code that runs then, as
a deferred trigger of the host's that reads a table by a name a temporary table can take, or a
deferred constraint checking a row the role can lock; the notifications the transaction queued, for
as long as writing them takes, which only `max_notify_queue_pages` bounds; and the operator's
settings of synchronous replication and prepared transactions, for as long as they let it. A role
given `TEMPORARY` can hold it too by the temporary tables its session makes, for as long as dropping
or emptying them takes, which a large `temp_buffers` lengthens, and by a temporary object's own
deferrable trigger, against which the check is best-effort; and a role given `USAGE` on a
foreign-data wrapper or a foreign server, or a privilege on a foreign table, or on a view or a
function that reaches one as its owner, by a remote transaction's commit, for as long as the remote
server has it wait.
With `track_commit_timestamp` on, `pg_xact_commit_timestamp` of a record's `TxID`, while the server
keeps it, shows when the transaction's commit was written, which an auditor can compare with its
`CommittedAt`.
`AsOf` makes no change: one tried is no actor's attempt, and `Config.OnRefused` isn't told of it. It
reads in a transaction, or under `WithTx` a savepoint of the host's, that it makes READ ONLY, so
nothing in its read writes, a hook's or the host's query either, but to a session's own temporary
table, and rolls back, which leaves a host's transaction as it was, writable where it was. It reads
history through views that migrating makes (`0028_as_of_views`), in a schema beside the package's
named as it with `_as_of` after, each named as the table it stands in for, which it names first on
its transaction's search_path: a statement there, the package's, a hook's through the `DB` it is
given or the host's on that transaction, reads a table by its name as it was then,
`rbac_group_members` too, and `current_schema()` there is the views' schema. So it makes no object
and takes no transaction id: it needs no `TEMPORARY`, and while its read runs it holds no `History`
or `Export` back, though under `WithTx` a host's transaction that has taken one holds them back, as
it would anyway, as does a write to a temporary table in the read; its snapshot, as any
transaction's, keeps vacuum from removing a row changed since it began, so keep each read short all
the same. So too it reads on a hot standby, as of what the standby has replayed, where `History`
fails: a time later than the standby's replay reads a change not yet replayed as not made, and
replay can cancel a long read there, as any standby's query, which is refused as `rbac.ErrConflict`.
Each read drops the session's cached plans (`DISCARD PLANS`), under `WithTx` the host's too, which
its statements plan again at their next run. The views read the tenant, the time and the cluster
`AsOf` sets for its transaction (`rbac.as_of_tenant`, `rbac.as_of`, `rbac.as_of_cluster`), with the
rights of whoever reads them, so a session that sets those itself reads through the views only what
it may read of history, and outside a read they read nothing, or fail, never the tables. A statement
of the read that leaves the search_path, the role, or one of those settings, set otherwise, or
another session revoking the role's `USAGE` on the views' schema, which the search_path then leaves
out, or dropping one of the views, would read another tenant or time, or the tables as they are now,
so `AsOf` fails once its read returns where one did: what the read answered stands only where `AsOf`
returns nil. One made and undone within the read it can't tell, and the package's statements run
between the two read by it: a call the read makes meanwhile, and those of a call after a hook of it
that made it. So set them, or the role, in a read or a hook only within a savepoint rolled back
before the package's next statement. The search_path it reads by names the views' schema, then
`pg_temp`, then the session's, as one that doesn't name `pg_temp` reads a session's own tables
first, so it refuses one that names `pg_temp` after the package's schema, as it would read them the
other way round, and one that names it first, which makes the session's temporary schema the current
one. A function, operator or type in the views' schema is found before the package's, and runs as
whoever reads, so `AsOf` refuses that schema where it holds more than its owner's views, another
role may create in it, or it isn't the role's that owns the package's tables, as a grant, an
extension installed there or a change of owner since migrating can make it. It finds the views by
the history they read, among those of the role that owns the package's tables and outside every
session's temporary schema, as migrating finds them among the role's that migrates: a view of
history named as one of the tables, that another session made in its temporary schema, as any role
with `TEMPORARY` that may read history can, or another role's, stood beside them before
`0033_view_seeks_and_hints`, and every read as of a time in the database failed while it stood, as
did migrating, which makes the views again. A statement looks each
name up by the catalog as it is then, whatever its transaction's snapshot, so what is made there as
a read runs is called by the read's next statement: `AsOf` checks the schema again once its read
returns, and fails where it has come to be so, on its own transaction once that has rolled back, as
a query of the catalog at its REPEATABLE READ reads the snapshot it began with. What was made there
and dropped again as the read ran it can't tell, which only a role that may create there can make:
its owner, which is the application's role where that role migrated, rather than the administrator's
role below, a member of it, a superuser, or one either lets. Under `WithTx` in a host's transaction
at REPEATABLE READ or SERIALIZABLE, whose queries read the catalog as of its first statement, both
checks read past what was made there since, or another role let create there: where that matters,
read on a pool's `Authorizer`, or under `WithTx` at READ COMMITTED. `AsOf` takes a time from 4714
BC, the earliest PostgreSQL holds, to 9999-12-30, the last the package stores, each to the
microsecond, rounded down, as pgx sends it: in 64 bits of microseconds from 2000, which a time past
year 294,000 or so wraps, so the database would read it as another, or refuse it.
A statement reads the history of the rows it names, as a check
does its subject's grants, groups and the denies on its resource's path, a search its subject's
grants, and the public's and the members' it counts, on each type it lists, and the custom roles
they name, and `Holders` the members of the groups it lists, not the whole tenant's: `AsOf` plans
every statement in its transaction for its arguments, the host's too, since a connection's cached
plan of a statement it has run often counts any tenant as an average one, and without JIT, as so
planned over history, they cost past `jit_above_cost` for an ordinary subject: a host's query of a
`Filter` condition for a subject of 249 grants on containers took 760 ms with JIT, almost all of it
compiling, and 110 ms without. It tests each version a statement reads for a later one by its
row's key, and `Holders` looks each identity's membership of the tenant up by its key, so
history's statistics, which autovacuum leaves until a tenth of it is new, change no read's cost by
much: a read of thousands of rows costs a few pages for each version. The test names the version's
entity as its own, so no index of history by scope serves it: through history's index of denies by
scope, read by the tenant and the time alone, every scope skipped, each deny a statement read cost
every later deny version of the tenant, and beside 6,000 denies on volumes binding its subject,
`Reachable` read 18 million pages of history, 4.4 s, and `Denies` of one volume 6,875 to list its
two, before `0033_view_seeks_and_hints`. It looks each version's
commit record up by its transaction, a few pages more, as `History` does for `CommittedAt`, so
what it answers turns on nothing an export leaves out. Joined to a group's members
by such statistics, the tenant's memberships were read again for each member, so `Holders` of a
group of 4,000 took 52 seconds, and 90 ms looked up by key. A list counts
the denies on scopes of its types by history's versions of them, at most a few, and `Grantable`,
which can offer any custom role, reads each version of every one once. It orders a row's changes
by their ids in `rbac_history`, which sessions take out of order once that table's id sequence
caches more than one, so `AsOf` refuses that. Its read's hooks run in its transaction, which holds
one of the pool's connections: a constraint there queries the `DB` it is given, as one that queries
the pool waits for another connection, which a busy pool may never free. The Authorizer its read is
given runs every call on that transaction, so use it from one goroutine at a time: for a review in
parallel, run several `AsOf` calls, each on its own goroutine (see Goroutines).

`rbac.PruneHistory(ctx, db, before, through)` deletes what an export has read past (`through`, its
cursor) and later records supersede: of each row, the last version counted by `before`, as `AsOf`
counts it, stays, so `AsOf` answers as it did for any time from then on, and refuses an earlier one,
and a row that had ended by then goes, once no version before its end stays; a transaction's commit
record goes with the last of its other records. One call deletes at most `rbac.MaxPrune` records,
commit records too: call it again while it deletes as many, and each goes on from where the last
stopped. It reads history that many records at a time, on a pool or a connection each in a
transaction of its own, so however long history is, none holds exports back for long. A transaction
that deletes records is recorded in history, with the last record it deleted in `History`'s order,
dated when its statement began, as any change is, so never before its `before` or a record it
deleted; one that deletes none changes nothing, and is not. A transaction that only prunes records
no commit, as no read counts a prune from one. `History` refuses the cursor of an export that began
before a prune where it is before the last record the prune deleted, as that export would read on
past what the prune deleted, so where several exports read history, `through` is the cursor of the
one furthest behind. It finds the prunes by the last record each deleted, so a prune through an
export's cursor, which deletes nothing the export hasn't read, costs its reads nothing, however
many there are while it catches up from the start or falls behind, and whatever history's
statistics count of them, as none before an analysis samples one; a prune reads only those of its
own time and cursor to go on from where the last stopped, and `AsOf` only the latest, so too. An
export from the start also reads the index's entries of the prunes before it began that deleted
past its cursor, until it reads past them. An export that began after the prune, as one from the
start after a refusal or a failover, reads history as the prune left it and isn't refused for it.
Where a cursor stands can't tell the two apart; `Cursor.Horizon`, the oldest transaction running as
its export began, does, so keep it with the cursor and each checkpoint, whose signature covers it,
and never set it: a later one would hide a prune since the export began. A cursor without it, as one
kept from an earlier release, is refused for any prune recorded after it that deleted a record after
it, and its export starts again from the start. While a transaction that took its id before a prune
is still running, a read from the start reads nothing, as its export would count the prune as one
since it began: while prunes that delete records come faster than the longest transactions end, as
they can while working through a long backlog, no export from the start begins. Run it on a
connection of the administrator's role below, which has the rights of history's owner, as the
application's hasn't, and keep what the host's audit retention requires: the federal floor is at
least a year. A delete from history that no prune its transaction records reaches, as one by hand,
is refused as the transaction commits, so no delete through history's triggers leaves an export
reading on past what it removed: `History` counts every prune of a transaction from an export's
`Horizon` on, whatever the id its record holds, which history's owner can choose, as the trigger
lets a delete through for any. Disabling the triggers takes a role with the rights of history's
owner, which the signed chain is kept against.

A role that owns a table can change it whatever its triggers say, and a schema's owner can drop
any table in it. So that the application's database role can't rewrite history or write around
it, that role is no superuser and holds no role that has a superuser's power or a way to it: not
`pg_write_all_data` or `pg_create_subscription`, through which it could write `rbac_history`
itself, nor `pg_execute_server_program`, `pg_write_server_files` or `pg_read_server_files`, with
which it could run any program as the server's operating system user, write any of its files, or
read any, as one that holds a superuser's password; before PostgreSQL 16 it has no `CREATEROLE`,
with which it could make itself a member of any role but a superuser, such as those or the roles
below; it has no `REPLICATION` attribute, with which it could read every data file over a base
backup, as `pg_read_server_files` can; from PostgreSQL 15 on, it has no `SET` or `ALTER SYSTEM`
privilege on a parameter only a superuser may set (`GRANT ... ON PARAMETER`), with which it could
have the server load a library or run a program of its choosing; and:

1. `Migrate` runs as an administrator's role the application's isn't a member of, with only the
   package's schema in its search_path, so that role owns the package's tables: their owner can
   disable the triggers that record them. Once they are made, `Migrate` as another role is refused,
   but as a superuser, which migrates as that role ([Running it](#running-it), Tables). A later
   migration can change history too, so the administrator's role keeps both owners' rights. It
   owns the schema of `AsOf`'s views too, named
   as the package's with `_as_of` after, which `0028_as_of_views` makes: that takes `CREATE` on the
   database, which a role that doesn't own it hasn't by default, so a superuser makes it first,
   empty, `CREATE SCHEMA <schema>_as_of AUTHORIZATION <administrator>` (the database's owner can
   only where it may `SET ROLE` to the administrator's), and grants no other role `CREATE` there,
   nor do the administrator's default privileges, which a schema made for it takes. `AsOf` names it
   first on its search_path, so migrating, and `AsOf` itself, refuse one that holds more than the
   views, is another role's, or in which another may create: a function, operator or type made
   there, as an extension installed there makes, would run in place of the package's, as whoever
   reads as of a time.
2. A role of history's own, which the administrator's role is a member of and the application's
   isn't, owns `rbac_history` and the functions `rbac_record` and `rbac_history_commit`: transfer
   them to it after migrating. A migration that makes such a function later, as
   `0029_commit_trigger` makes `rbac_history_commit`, gives it to `rbac_record`'s owner itself, or
   fails.
   It needs `USAGE` on the schema, since every write to the package's tables runs `rbac_record`
   as it, which refuses the write without it; `EXECUTE` on the functions `rbac_tenant_keys` and
   `rbac_text_array`, which history's index of the keys denies name calls for each record, and
   which every role has unless it is revoked; and `CREATE` there to be given them, unless a
   superuser gives them, or, for one a migration gives it, the schema's owner migrates, which grants
   it for the migration alone.
3. The application's role has `USAGE` on the package's schema, without which it reads none of its
   tables; `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the package's tables but `rbac_history`,
   `rbac_expired` and `rbac_migrations`, and on any a later migration adds; `EXECUTE` on the
   functions `rbac_group_members`, `rbac_tenant_keys`, `rbac_text_array` and `rbac_changes_grants`,
   which every role has unless it is revoked, and on `rbac_expired_through`, through which
   `DeleteExpired` records the times it deleted by, and which no role has unless it is granted;
   only `SELECT` on `rbac_expired`, which every check and change reads, so that role can neither
   record a time past the database's clock nor move back the latest, as only that function writes
   it, and nothing on its id's sequence, with which `setval` could fail every run of
   `DeleteExpired`; and only `SELECT` on `rbac_history`, with no `UPDATE` on its
   id sequence, which a grant on all the schema's sequences can give: `setval` could number a change
   below the one before it, and `AsOf` would read the row as it was before the change. Never
   `TRIGGER`, which `ALL` includes: a trigger runs its function as whoever writes the table, and one
   on `rbac_history` can drop each record, as history's owner. And `USAGE` on the schema of `AsOf`'s
   views and `SELECT` on them, which `AsOf` refuses to read without, rather than read the tables as
   they are now: they read history with the rights of whoever reads them, so they give a role no row
   of history it couldn't read already, but for `USAGE` on the package's schema, which a view
   reading history by its oid doesn't ask of whoever reads it. Migrating gives them to every role
   that may then read history and use the package's schema; give them to one given both after, as
   `SELECT rbac_as_of_views()` run as the administrator's role does to each such role then, and
   revoke them from one that loses either, as it takes them from none.
4. The application's role can make no schema and create in none, the schema of `AsOf`'s views
   either: it neither owns the database nor has `CREATE` on it, which `CREATE SCHEMA` needs and only
   the owner has by default, and it creates in no schema it owns, as `public` is when that role owns
   the database, nor in `public` before PostgreSQL 15, where every role can. `Migrate` calls
   functions by name, and an overload made in the package's schema would run in its place, as the
   administrator's role; and the package's schema is a session's current one, the first on its
   search_path, which a session can set, so one that named first a schema the role made, or can
   create in, would read a table made there as history: a generation of its own, which an export
   starts from `Genesis`, and `Export` would sign what it holds. `History` and `Export` can't tell
   that table from history's own, which the application's role owns where these roles aren't set up,
   so they don't refuse it.

A role that may create temporary tables, as every role may unless `TEMPORARY` is revoked from
`PUBLIC`, reads its session's own tables and types before any schema's of the same name until it
ends, which in a pool can be long after the call that made one. One named as a package's table
stands in for it in that session, whose checks are the role's own to make, but for `AsOf`'s, which
read their views first; `History`, `Export` and `PruneHistory`, and `AsOf`'s checks of history, name
history's table by the package's schema and their types by pg_catalog's, so none stands in for them,
and refuse a search_path that names pg_temp first. And history's triggers find history beside the
table each fires on, whatever the schema is named, or refuse the row where their search_path can't
name that schema, before they read a table or call anything by it: so none stands in for the history
a change is recorded in, or a prune checked against, and nothing such a table runs, as its row
security policy, runs as history's role.

Harden temporary objects too: revoke the `TEMPORARY` privilege on the database from `PUBLIC`, which
holds it by default, and grant it back to none of these roles. The commit record refuses a
transaction that commits a change to the package's tables while the session has an enabled deferrable
trigger on a temporary table, as that trigger would run the session's own code after the change is
dated; but that check, read against the catalog as the commit record is written, is a best-effort
defense, so a role that need not make temporary objects is better left unable to. No call of the
package's makes one, `AsOf` included, which reads views migrating made, so none of the roles needs
`TEMPORARY`, and the check holds against each.

Harden foreign data too: grant the application's role no `USAGE` on any foreign-data wrapper or
foreign server, and no privilege on a foreign table, none of which PostgreSQL grants `PUBLIC` by
default. A transaction that reads or writes a foreign table through postgres_fdw commits its remote
transaction after its commit record is written, and waits for the remote server for as long as that
has it wait, which nothing the package sets bounds (see above): `USAGE` on a server lets a role map
itself to it, `USAGE` on a wrapper lets it make a server, and a privilege on a foreign table lets it
read or write through a mapping for it, or for `PUBLIC`, without either. Nor grant it
`pg_read_all_data`, which reads every foreign table as one it may read, nor a privilege on a view,
or `EXECUTE` on a function that runs as its owner (`SECURITY DEFINER`), that reads or writes a
foreign table: through either, the owner's mapping, or one for `PUBLIC`, opens the remote
transaction, with no privilege of the role's own on the table, server or wrapper. Nor let it reach
any other extension that does work it can start, and wait on, in a pre-commit callback. No call of
the package's uses foreign data, so none of the roles needs any.

## Running it

- **Tables:** `rbac.Migrate` creates them, prefixed `rbac_`, in the connection's current schema,
  in a database whose encoding is UTF8, and records what it applied in `rbac_migrations`. It never
  runs by itself; a host with a migration tool of its own can apply `rbac.Migrations()` instead.
  It applies each pending migration in a transaction of its own, which records it as it commits:
  so a migration takes its locks in the order it names them, whatever was pending before it, and a
  failure leaves the database at the last migration recorded, from which migrating again goes on.
  The package's calls don't check what the database was migrated to: make them from a replica only
  once its own migrations are applied, as `Migrate` returning nil says.
  Only the role owning the package's tables migrates them, the administrator's of
  [History](#history): a migration makes what it makes its maker's, and from `0028_as_of_views` on
  checks the schema of `AsOf`'s views against it, which `AsOf` finds among that role's views. So
  once the tables are made, `Migrate` as another role is refused, as `rbac.ErrInvalid` naming the
  role owning them, before it applies anything or takes any lock, but as a superuser, which runs
  each migration as that role, by `SET LOCAL ROLE`, and is itself again after: a superuser's
  migration makes and checks what that role's own would, and fails where that one's would, as
  where it may not make the views' schema or give `rbac_history_commit` to history's role, saying
  what to do. A tool of the host's own applies them as that role too. Before this release, a
  superuser's migration of tables another role owned ran as itself: from before `0028_as_of_views`,
  it made the views' schema, the views and `rbac_as_of_views` its own, so `AsOf` refuses every read,
  saying what to run, as it reads only the views of the role owning the tables; from `0028` on, it
  failed at `0033_view_seeks_and_hints`, as the views' schema was that role's; and it made
  `rbac_expired`, `rbac_expired_until` and `rbac_expired_through` its own where it made them, as it
  made its own whatever else a migration it applied made, as `rbac_changes_grants` where it applied
  `0021_grant_denies`, which a later migration, as that role, can't alter. To give them
  back, a superuser, with the package's schema first on its search_path, runs
  `ALTER TABLE rbac_expired OWNER TO <administrator>`,
  `ALTER FUNCTION rbac_expired_until() OWNER TO <administrator>` and
  `ALTER FUNCTION rbac_expired_through(timestamptz) OWNER TO <administrator>`, and the same,
  `ALTER TABLE`, `ALTER FUNCTION` or `ALTER STATISTICS`, for each other table, function or
  statistics object in that schema that is still the superuser's, but history's table and
  functions, which go to history's role, as [History](#history) says; where `AsOf` refuses
  every read, as its error says, `ALTER FUNCTION rbac_as_of_views() OWNER TO <administrator>`,
  `DROP SCHEMA IF EXISTS <schema>_as_of CASCADE` and
  `CREATE SCHEMA <schema>_as_of AUTHORIZATION <administrator>`, and then the administrator's role
  runs `SELECT rbac_as_of_views()`, which makes the views again and gives them to each role that
  may read history; and where `0033` failed, migrate again.
  On a host's transaction, a `pgx.Tx` or a `DB` whose `Begin` gives a savepoint of one, it applies
  them all in one savepoint, and refuses any isolation but READ COMMITTED: a stricter one's snapshot
  would miss the writes it waits for. Call it there before any change to the package's tables: from
  `0027_commit_dates` on, each record of history a change writes holds an event deferred to the
  commit, as from `0020_recorded_prunes` on each record `PruneHistory` deletes does, and PostgreSQL
  alters no table whose events are pending, as migrations up to `0032_expired_writes` alter
  history, so where one of those is pending, `Migrate` refuses, as `rbac.ErrInvalid`, a
  transaction holding such events, before it waits for another replica's migration or applies any.
  A tool of the host's own applies them before any such change too.
  A migration locks what it changes until it commits, and while it waits for a lock, every check,
  list and change of that table queues behind it, and of those it locked already. So `Migrate` has
  it wait at most 100 ms for any lock: a change that reads the tables in another order than a
  migration locks them would otherwise deadlock with it, as no order suits every change
  (`ChangeMembers` reads eligibilities and denies before custom roles, `DeleteRole` custom roles
  before eligibilities), and a transaction holding a table for long would stall them all. It then
  rolls it back and tries it again, waiting longer each time, up to 10 times over about 20 seconds,
  and then fails as `rbac.ErrConflict`: migrate again once what held the table, as a long export or
  host transaction, has ended. A wait that short ends before PostgreSQL's deadlock check, which runs
  once a wait passes `deadlock_timeout` and alone cancels an autovacuum worker holding the table, as
  one vacuuming a large history can for minutes: where one holds a table of the package's as a
  migration gives way, the next try first takes that table's `SHARE UPDATE EXCLUSIVE` lock, waiting
  a second past `deadlock_timeout` whatever the session's `lock_timeout`, so PostgreSQL cancels the
  worker, and only then the migration's own locks. No check, list or change takes a lock that one
  conflicts with, so none waits behind it, and none of the migration's is held yet. A worker on a
  table the migration doesn't lock is canceled too; one vacuuming to prevent wraparound, which
  PostgreSQL never cancels, holds the table until it ends, and the try goes on without that table's
  lock once the wait ends, to the other tables' waits and then the migration, and each try after
  waits so again: some 20 seconds more over the 10 tries for each such table, with the default
  `deadlock_timeout`. A role without `pg_read_all_stats` can't read other sessions' backend types,
  so it can't tell autovacuum's vacuums and analyses from a client's, and a client's `VACUUM` of a
  table has it wait so too. A transaction waiting for a lock a migration holds, which holds one the
  migration then waits for, is still ended as a deadlock where its `deadlock_timeout`, 1 second by
  default, passes before the migration's wait does, and a call ended so, or by its session's
  `lock_timeout`, a read or a change, before its transaction or in it, is refused as
  `rbac.ErrConflict`. A tool of the host's own gets none of this: apply each migration in a
  transaction of its own with a short `lock_timeout`, on SQLSTATE 55P03 or 40P01 roll it back and
  apply it again, and where an autovacuum worker holds one of the package's tables as it gives way,
  first lock that table `IN SHARE UPDATE EXCLUSIVE MODE` with a `lock_timeout` past
  `deadlock_timeout`, and then apply the migration with the short one. Nor does `Migrate` on a
  host's transaction, as rolling back to its savepoint frees nothing the host's transaction took
  before, which what the migration waits for can be waiting for in turn, as a request that read the
  package's tables and then reads a table of the host's that transaction altered: it waits as that
  transaction's `lock_timeout` says, for PostgreSQL to end such a wait as a deadlock. On any
  connection, it waits for another replica's migration as long as the session's `lock_timeout` lets
  it, and where that ends the wait fails as `rbac.ErrConflict` without trying again.
  A migration that rebuilds an index, as `0009_grant_seeks` rebuilds two of `rbac_grants`, locks
  the table until it commits, so checks, lists and changes wait for the rebuild; one that builds
  an index, as `0011_tenant_keys` builds three on `rbac_eligibilities` and `rbac_denies`, keeps
  writes to the table waiting until it commits, though reads go on: on a large table, migrate when
  that wait is acceptable. Code from before `0012_activation_through` must not run beside code
  after it: an activation it extends keeps the eligibility recorded before, and can outlast the one
  it was extended through. Stop the replicas running it before migrating, and don't start them
  again once `rbac_migrations` records 12, even where `Migrate` failed on a later migration, as it
  records each as it commits. `0013_bounded_rows` locks every table, history too, until it
  commits, and reads each once for each check it adds, so checks, lists, changes and reads of
  history wait for it. `0015_history_seeks` builds two
  indexes on `rbac_history`, which every change writes, and analyzes it, so changes wait until it
  commits. Building one calls `rbac_tenant_keys` and `rbac_text_array` as history's role, as
  recording each deny does from then on, so it grants that role `EXECUTE` on both where it lacks
  it. Where new functions give PUBLIC no `EXECUTE`, grant it on `rbac_text_array` to the
  application's role too, as `AsOf` calls it. `0016_flat_lists` rewrites a list a role, deny or
  eligibility holds in more than one dimension, or from a subscript other than 1, as a write
  around the package could store, in one dimension from 1, keeping its elements in order, which
  history records as `Migrate`'s change, and then refuses another shape. It locks those three
  tables until it commits, so checks, lists and changes wait for it, reads each twice, and keeps
  changes to every table waiting, as each writes history. It reads every deny record in history
  while it holds them, though reads of history go on; but where one holds its keys in more
  dimensions, it rebuilds history's index of them, which reads all of history, and as a read of a
  table locks each of its indexes, the rebuild waits for the reads of history running, as an
  export, every read of history waiting behind it until migrating commits, and gives way where one
  runs past the wait. A transaction that read history and then reads one of those tables waits for
  migrating while it holds what the rebuild waits for: the rebuild gives way, unless the
  transaction began waiting long enough before it, as while migrating reads a long history's deny
  records, for its `deadlock_timeout` to pass first, and PostgreSQL ends the transaction.
  `0019_principal_seeks` builds an index on `rbac_grants`, which keeps writes to it waiting until it
  commits, though reads go on, and rebuilds history's index of a principal's versions, which reads
  all of history, and analyzes it. It locks `rbac_grants` and then history before it builds either,
  in a transaction of its own, whatever was pending before it, so reads of history, and every
  change, as each writes history, wait until it commits too, and only a transaction under way as it
  starts that read history or made a change, as deleting a scope's eligibilities and then its grants
  does, and then writes a grant can make it give way.
  `0020_recorded_prunes` builds an index of prunes' records on history, which reads all of history,
  and adds the trigger that refuses a delete from history no prune records. It locks history against
  writes before either, so every change, as each writes history, waits until it commits, though
  reads of history go on, and a transaction under way as it starts that made a change can make it
  give way. A prune by an earlier release records itself without the last record it deleted, in a
  statement after its delete: it still deletes, but not in a transaction that sets constraints
  immediate, and `History` refuses an export's cursor before the one it went through. The trigger
  checks each record a prune deletes as its transaction commits, which took a window of 10,000
  records about twice as long to delete.
  `0021_grant_denies` builds an index on `rbac_denies` of the denies that remove a power to change
  grants, which keeps writes to it waiting until it commits, though reads go on. Its predicate calls
  the function `rbac_changes_grants`, which it adds, so every role writing a deny calls it from then
  on, as `ChangeMembers` and `DeleteGroup` do reading the denies: where new functions give PUBLIC no
  `EXECUTE`, grant it to the application's role.
  `0022_prune_seeks` builds an index of prunes on history by the last record each deleted, which
  reads all of history, so every change, as each writes history, waits until it commits, though
  reads of history go on, and a transaction under way as it starts that made a change can make it
  give way. Only prunes have entries. Without it, `History` read every prune recorded since a cursor
  that fell behind, or since an export catching up from the start began, from history's rows, twice
  in each call and once in each window of a prune: a read of one record from such a cursor took
  1.3 ms with no prune since, 14 ms with 20,000 and 78 ms with 80,000, and with it 1.2 ms with any.
  `0023_history_schema` replaces `rbac_record` and `rbac_history_pruned`, which keep their owners
  and who may execute them, so history's role still owns `rbac_record`. It takes no lock on the
  tables: changes go on while it is applied, each recorded as before until it commits. Each
  function then finds history in the schema of the table it fires on, which costs a row recorded
  about a microsecond of the 70 to 100 it takes, and refuses the row where its search_path can't
  name that schema: a search_path reads `$user`, however it is quoted, as a role's name, and leaves
  out a schema the role has no `USAGE` on.
  `0024_record_refuses_first` replaces `rbac_record` again, which keeps its owner, who may execute
  it and its settings, and takes no lock on the tables, as `0023_history_schema` does. Before it,
  `rbac_record` read the row's last record from history before it refused a search_path that can't
  name the table's schema: where history's role had no `USAGE` on the schema, or the schema was
  named `$user`, it read a session's own table named as history's, as that role, and whatever the
  table runs, as its row security policy, ran with that role's rights before the row was refused.
  What a rollback doesn't undo stayed, as setting history's id sequence back, after which a row's
  later records are numbered below its earlier ones, and `AsOf` reads it as it was before them. It
  now refuses before it reads a table, or calls a function or an operator its search_path finds.
  `0025_broad_and_member_seeks` rebuilds `rbac_grants_custom_principal`, the index `Filter`,
  `Reachable` and `Holders` read the custom roles the public's and the tenant's members' grants
  name by, with a predicate of its own, which their statements name in place of the custom roles'
  index's: so that index, which leads to the tenant alone, serves no plan of them whatever the
  statistics, where by statistics from before a tenant granted custom roles, or with none, they read
  every grant of one in the tenant through it. It locks `rbac_grants` until it commits, so checks,
  lists and changes wait for the rebuild. Code from before it names the old predicate, which the
  index no longer serves, so until every replica runs this release their searches read those grants
  through another index, as the statistics have the planner pick. It also replaces
  `rbac_group_members`, which keeps its owner and who may execute it and takes no lock on the
  tables, to read a group's members and then their memberships planned for their number, so
  `Holders` of any release reads a small group's members alone whatever other tenants call theirs.
  `0026_conditional_seeks` builds an index of conditional grants on `rbac_grants` and one of the
  eligibilities with a requirement on `rbac_eligibilities`, the eligibilities' first, as most
  changes writing both write them first, which keep writes to each table waiting until it commits,
  those to eligibilities while it builds both, though reads go on. A `DeleteRole` under way as it
  starts, which deletes the role's grants before its eligibilities, can make it give way. A
  conditional grant, and a group's eligibility with a requirement, is bounded with those beside it
  on its scope, read under the scope's lock: without them, every grant to a group on the scope, or
  every eligibility there, was read from the table to find those, so a conditional grant to a
  group beside 80,000 unconditional ones on a tenant took 39 ms, against 7 ms unconditional, and by
  statistics from before they were made, every grant in the table was read. Code from before it
  and after it run beside each other, applied or not: only what those reads cost turns on it.
  `0027_commit_dates` locks history against reads and writes until it commits, so every change, as
  each writes history, and every read of history, as `AsOf` and an export, waits for it; it adds
  history's `cluster` column, null for every record before it, which reads no row, rebuilds
  history's index of an entity's versions and its index of scopes, and builds an index of commit
  records, each of which reads all of history: 3 seconds for 500,000 records, 631 MB of history, on
  a test server, and in proportion to history's size. `CREATE INDEX CONCURRENTLY`, which would let
  changes go on, can't run in the transaction `Migrate` applies a migration in. It replaces
  `rbac_record`, which keeps its owner and who may execute it, so history's role still owns it, and
  adds the constraint trigger `rbac_history_committed`, which runs it as each transaction that
  changes the tables commits, to write the transaction's commit record as history's role. Its checks
  of what a record's entity and op are, wider than those they replace, which held every record, are
  added without reading history (`NOT VALID`). Run `History`, `Export` and `PruneHistory` only from
  code at or after it: earlier code exports a transaction's commit record as a record of its own,
  which a later export doesn't, so the two chain history apart, and prunes by the records' own
  dates, deleting versions `AsOf` now reads; its `AsOf` counts changes from their own dates, as
  before. From it on, a transaction that changes the package's tables, the package's own or a
  host's, fails as it commits with SQLSTATE 0A000 where it declared a cursor `WITH HOLD`, or where
  its session has an enabled deferrable trigger on a temporary table: declare the cursor in a
  transaction of its own, or without `HOLD`, and drop or disable the trigger, make it `NOT
  DEFERRABLE`, or change the package's tables on another connection. The rest of its commit, from
  its commit record on, waits for a lock at most 100 ms where its `lock_timeout` is longer, and
  fails past it with SQLSTATE 55P03, as where another session holds one of its session's temporary
  tables, or a transaction with `NOTIFY` waits behind many others committing theirs: retry it. It
  fails with SQLSTATE 42501 where its session set `rbac.cluster`, the setting history stamps each
  record's cluster from, to another than the server's: reset it. A host transaction may set its
  constraints immediate, by name or `ALL`, before or after its changes:
  `rbac_history_committed` is deferred again as it fires. And `AsOf` under `WithTx` no longer counts
  the host transaction's own changes, which haven't committed, where earlier code counted those
  dated by its time: read them after the transaction commits.
  `0028_as_of_views` makes the views `AsOf` reads history through, one of each of the package's
  tables, in a schema beside the package's named as it with `_as_of` after, and the function
  `rbac_as_of_views`, which makes them again for a later migration that changes a table. Making the
  schema takes `CREATE` on the database: where the role migrating hasn't it, the migration fails
  with SQLSTATE 42501, recording nothing, until a superuser makes the schema for that role, empty,
  as the roles above say, and one that holds anything, is another role's or in which another may
  create, as the role's default privileges can have it, fails it with SQLSTATE 42P15, as does one
  that has come to be so when a later migration makes the views again. It gives the views and their
  schema to each role that may read history and use the package's schema then, as the application's
  role above, so that role needs no new grant, and `rbac_as_of_views` does again to each that may
  when it runs. It takes no lock a check, a change or a read of history waits for. Code from before
  it makes temporary views for `AsOf`, as it still may beside it, and code from it on reads these,
  refusing as `rbac.ErrInvalid` to read as of a time where they aren't made: migrate before running
  it. From it on `AsOf` needs no `TEMPORARY`, so once no replica runs code from before it, revoke it
  from `PUBLIC` with no exception; and it takes no transaction id, so its read holds no `History` or
  `Export` back. Hooks and a host's queries on its transaction read the package's tables by name as
  of the time, as before, but its read runs READ ONLY, with the views' schema first on the
  search_path: `current_schema()` there names the views' schema, a write there but to a temporary
  table fails with SQLSTATE 25006 rather than roll back with the read, and one that leaves the
  search_path, the role, `rbac.as_of`, `rbac.as_of_tenant` or `rbac.as_of_cluster` set otherwise
  fails `AsOf` as `rbac.ErrInvalid` once its read returns, as does the views' schema holding more
  than the views, or another role being able to create there, when the read begins or as it ends, or
  one of the views dropped as it ran. Drop the views' schema with the package's: dropping the
  package's drops the views, which read its history, but not their schema.
  `0029_commit_trigger` has `rbac_history_committed` run a function of its own,
  `rbac_history_commit`, in place of `rbac_record`. The trigger fires as a transaction commits once
  for each record the transaction wrote, which ran with `rbac_record`'s settings and start and read
  to the end of an index page for a later record of the transaction: about 12.5 µs a record on a
  test server, 250 ms of `COMMIT` for 20,000 records, a fifth of what writing them took, and some
  12 s for a million, which a `statement_timeout` can end. It now looks among the next 32 ids first,
  as a statement's records take ids one after another, or nearly: about 8 µs a record, 160 ms for
  20,000. Where none of those is the transaction's, as where more than 32 sessions write history at
  once, record by record, it reads both, about 15.5 µs. It replaces the trigger, which locks history
  against reads and writes until it commits, so every change, as each writes history, and every read
  of history, as `AsOf` and an export, waits for it, and a transaction under way as it starts that
  made a change can make it give way. The role migrating makes the function, which writes history as
  its owner, and gives it to `rbac_record`'s owner, history's role where the roles are set up as
  [History](#history) says: as a role that may `SET ROLE` to history's role, as the administrator's
  may, where that role has `CREATE` on the schema or the role migrating may grant it that, as the
  schema's owner can, which it does for the migration alone, or as a superuser owning the tables.
  Otherwise migrating fails with SQLSTATE 42501, having changed nothing, rather than leave the
  function to another role: grant history's role `CREATE` on the schema, or history's role to the
  role migrating with the `SET` option, as its hint says, and migrate again. A superuser's migration
  of tables another role owns runs as that role, as above, so it fails alike, and the hint no
  longer offers one. No role but its owner may execute it, nor
  `rbac_record`, which writes history as its owner too, as only their triggers call them: migrating
  revokes `EXECUTE` on both from every other role, `PUBLIC` included, as the schema's default
  privileges can grant it as each is made, where `0003_history` revoked it on `rbac_record` from
  `PUBLIC` alone; a role holding it could attach either to a table of its own in `pg_temp`, whose
  triggers would then run as history's role. It replaces `rbac_record` too, which keeps its owner
  and its settings, without its path for a commit record, which no trigger reaches any more. A
  procedure or a `DO` block that changes the package's tables with a cursor `WITH HOLD` open that it
  declared in an earlier transaction is refused as before, as nothing tells that cursor from one
  declared in the transaction committing: its refusal now says so, and how such a batch commits.
  `0030_expired_through` adds `rbac_expired`, the times `DeleteExpired` deleted by, which every
  check, search and change of code after it reads and every `DeleteExpired` writes, and gives each
  role holding `SELECT`, `INSERT`, `UPDATE` or `DELETE` on `rbac_grants` the same on it, as the
  application's role of step 3 holds them, so a deployment that gave its roles their privileges
  before migrating runs code after it with no step of its own; give a role you give its privileges
  only after migrating those on it too. Code after it, run before it is applied, fails every check,
  search and change, as the table doesn't exist. It takes no lock on the other tables. History
  doesn't record it, and `AsOf` doesn't read it. Code before it never reads it. Run `DeleteExpired`
  only from code after it once any runs: an earlier one records nothing, so the reads of later
  code can find what it removed by a clock ahead of theirs.
  `0031_member_reads` replaces `rbac_group_members` again, which keeps its owner and who may execute
  it and takes no lock on the tables, to plan its statements with sequential scans off, by its SET
  clause, whatever its caller's: it reads the groups' places a group at a time, in the order of the
  primary key, and the members' memberships by their keys, through a bitmap where a plan counts
  them as many, and each on its own where it counts them as few, as in a tenant holding a small share
  of the table, though none the keys don't name.
  Code from this release runs every statement calling it with them off, so its join of a group of
  20,000 to their memberships, as before, looked each up on its own, 20,179 pages that fill 856, and
  code from before it reads the places by statistics alone, every place in the table by those from
  when it was nearly empty. Code from before it and after it run beside each other, applied or not.
  `0032_expired_writes` has history record every write to `rbac_expired`, as the entity `expired` in
  no tenant, keyed by an id it gives each row, as two can hold one time, replacing `rbac_record`,
  which keeps its owner and who may execute it, and widening history's check of entities, which
  reads no record but locks history against reads and writes until migrating commits, so every
  change, as each writes history, and every read of history, as `AsOf` and an export, waits for it.
  Adding the id locks `rbac_expired` against reads and writes until migrating commits too, so every
  check waits for it as well, for as long as `Migrate` waits for a lock and then runs. It records
  each row the table holds as its baseline, brings a time past the database's clock back to it,
  recorded as an `update`, and from then on refuses one past the clock, whoever writes it, by a
  trigger, `rbac_expired_until`, which no role but its owner may execute. It takes from every role
  but the table's owner every privilege on it but `SELECT`, on the table and on its column,
  `TRIGGER` too, which would run a role's function as whoever writes the table, and every privilege
  on the id's sequence, which the schema's default privileges can grant as it is made. It gives
  `EXECUTE` on `rbac_expired_through`, which it makes, to each role that held `INSERT` on the table
  or its column, as `0030_expired_through` gave the application's role of step 3, and to no other,
  so a deployment that gave its roles their privileges before migrating runs `DeleteExpired` with no
  step of its own; grant it to a role you give its privileges only after migrating. The function
  runs as the table's owner, which it is given where another role migrates, and is SQL bound to the
  table as it is made, so nothing a session names changes what it writes. A trigger already on
  `rbac_expired` that runs a function a role other than the table's owner or a superuser owns, as a
  role that held `TRIGGER` on it, which step 3 never gives, could have made, would run that role's
  code as the table's owner whenever the function writes the table: migrating refuses it with
  SQLSTATE 42501, having changed nothing; drop it, and migrate again. Code before it runs
  `DeleteExpired` by writing the table, which the application's role of step 3 may no longer, and
  fails with SQLSTATE 42501, and code after it, before it is applied, by the function, which doesn't
  exist yet, and fails as `rbac.ErrInvalid`, saying so: run `DeleteExpired` only from code after it
  once it is applied. Their checks, searches and changes run beside each other, applied or not.
  Code from before advisory locks were keyed by SHA-256 must not run beside code after it, so a
  rolling upgrade across the two is unsafe: they key every lock apart, so a change by one waits for
  none by the other, and what each checks under its locks can change before it commits, as two
  changes each giving an identity one value of an Exclusive dimension can both commit. Stop every
  replica running the earlier code before starting any running the later, and don't start one of
  the earlier again: no migration records the change, so nothing refuses it. `Migrate`'s own lock
  is keyed anew too, so a replica of each doesn't wait for the other's migration, which matters only
  where the two run at once.
- **Renaming the schema:** from `0023_history_schema` on, `ALTER SCHEMA ... RENAME` keeps history:
  its triggers find it beside the table each fires on, whatever the schema is named, and a
  generation names the schema by its OID, so exports read on from their cursors and checkpoints.
  Migrate to it first: before it, they find history by the name the schema had when they were
  made, so after a rename a change fails, or is recorded in a table its session made of its own,
  and a prune recorded in such a table lets a delete from history through. Rename while nothing
  reaches the tables, and then set the search_path of every role and pool to the new name: changes
  wait for each other by locks named for the schema, so one under way by the old name holds none
  back by the new, and a session still on the old name finds no tables, or tables of its own of
  those names. Never name the schema `$user`, which no search_path can name: every change there is
  refused. Never move one of the package's tables to another schema: its changes would be recorded
  in that schema's history, or with none there, in a session's own table of its name. `AsOf` finds
  its views by the history they read, whatever either schema is named, so renaming either keeps it
  reading.
- **Goroutines:** an Authorizer `New` returns on a pool is safe for concurrent use. One bound to a
  transaction or a connection, as `WithTx` and `AsOf`'s read give and `New` returns on a `pgx.Tx`
  or a `*pgx.Conn`, runs every call on that one connection, so it is for one goroutine at a time,
  as the `pgx.Tx` or connection is: concurrent use isn't supported, and pgx may fail, race or
  panic. For an access review in parallel, run several `AsOf` calls on a pool's Authorizer, each on
  its own goroutine, in a transaction of its own. Hooks may call back in, one call at a time, as
  from the call that asks them. Under `WithTx`, make `AsOf`'s read's calls on the Authorizer it is
  given: one on the Authorizer `AsOf` was called on runs in `AsOf`'s savepoint, and reads the past.
  On a DB of the host's own, it is as safe for concurrent use as that DB.
- **Transactions:** a change runs in its own transaction at READ COMMITTED, or under `WithTx` in
  the host's, which must be READ COMMITTED too. A call PostgreSQL refuses for a race, as a
  serialization failure, a deadlock between host transactions, or a lock it waited for past the
  session's `lock_timeout`, matches `rbac.ErrConflict`, still wrapping PostgreSQL's error, as does a
  change refused because what it rests on changed while it waited: try it again. It does wherever in
  the call PostgreSQL refused it: in a change's transaction or the reads it makes before it, in a
  read, or in a statement a hook ran, where the hook's error wraps PostgreSQL's, alone or beside
  other errors, as `errors.Join` holds them, or holds it as `errors.As` reads it. Under `WithTx`,
  roll the host's transaction back and run it again from its start, not the call alone in it: a
  statement refused on that transaction itself, as most reads', a hook's or one a change makes
  before its savepoint, aborts it, and one refused in a savepoint, as a change's, `AsOf`'s or
  `History`'s, leaves it holding what it took before the call, which the race can be over. The
  signer `Export` and `Checkpoint.Sign` are given is a hook too. A hook's error is read in the
  order `errors.Is` and `errors.As` read it, however many errors it holds, to the first race or
  `ErrConflict` in it, and once ten thousand or so of them are read, each one once: one whose tree
  holds itself, as a host's type wrapping itself by mistake can, which they read forever, a call
  reads round until then and returns, though the host's own `errors.Is` of what it returns, or of
  what `Config.OnRefused` is told, can still read it forever. Changes to the same rows wait for
  each other by locks named for the schema holding the tables, so sessions reaching them through
  different search_paths still do. A host's transaction that changes the package's tables commits
  having declared no cursor `WITH HOLD`, nor with one open that an earlier transaction of its
  procedure, `DO` block or query string of several statements declared, and with no enabled
  deferrable trigger on a temporary table of its session: history refuses each as the transaction
  commits, with SQLSTATE 0A000, as it would have its changes counted before they commit (see
  History), or where constraints were set immediate, as the statement that did, or the first change
  after it. And the rest of its commit waits for no lock past 100 ms, failing with SQLSTATE 55P03,
  where its `lock_timeout` is longer.
- **What the host passes:** a check reads grants, memberships and groups as they are; only
  conditions, compiled or found not to compile, are cached. Read a resource's ancestors and
  attributes from where they are stored, never from request input, no earlier than the content
  they protect, and from the primary. A deny is only as complete as the ancestors passed.
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
- **Limits:** a change takes at most `rbac.MaxBindings` bindings, and the members one
  `ChangeMembers` adds gain at most as many grants and eligibilities, each member's counted apart,
  by its principal, but no more than one place alone gains, while `ImportMembers` asks
  `ValidateGrant` about each one its members gain; a principal holds a role on a scope at most
  `rbac.MaxGrantsPerRole` times, and is in a group at most `rbac.MaxPlacesInGroup` times, by source,
  and directly in at most `rbac.MaxGroupsOfPrincipal` groups, from each source the host owns apart,
  which bounds the groups a check reads through others only level by level, so keep nesting narrow;
  a scope holds at most `rbac.MaxDenies` denies; a tenant has at most `rbac.MaxCustomRoles` custom
  roles; an id is at most `rbac.MaxID` bytes. The others are exported beside them. Lists have no
  limit or cursor, so what one returns grows with what it lists: `Memberships` of a whole tenant
  with its members and guests, `MembershipsOf` with the tenants an identity is a member or guest of,
  `Groups` with its groups, `Members` with a group's members, `GroupsOf` with the groups a principal
  is in, through others too, `Holders` with who holds the permission, `Grants` and `Eligibilities`
  on the tenant's scope with what is granted there, `Reach.Scopes` with the scopes a subject's
  grants are on, and `Conflicts` with the identities in conflict. In a large tenant, ask for less:
  `Memberships` of named principals, `Grants` of one principal.
- **JIT:** turn JIT compilation off for the application's role, as in
  `ALTER ROLE app SET jit = off`, which a session takes as it starts, so a pool's connections take
  it once they reconnect. The planner can't tell how far a walk of a subject's groups goes, so for
  a subject in many groups it costs every check, and Activate, far past `jit_above_cost`, and each
  call then compiles its statement before running it, which takes longer than running it: for an
  identity in 1,000 groups, a check took 550 ms, and 120 ms with JIT off, and Activate's statement
  spent 500 of its 650 ms compiling. As of a time, every statement costs so for any subject, as
  planned for its arguments over history: `AsOf` turns JIT off in its own transaction, which the
  rollback puts back, whatever the role's setting.
- **Planner settings:** every statement a check, list or change sends to read the package's tables,
  but as of a time, turns sequential scans off for itself, as `Holders`' read of label values and
  `Conflicts` turn JIT off for theirs; and each that finds rows by where they are stored, as places
  in groups, which have no id, turns TID scans on, should the host's session have them off, as with
  them off too a plan read every place to remove one. Each sets them in the round trip that sends
  the statement, several of a change's together, and puts the session's back after it, keeping each
  meanwhile in a variable of the package's own named for it, as `rbac.enable_seqscan` and
  `rbac.jit`: a connection plans a statement once for all its runs, and one planned while a table
  fit in a page read every row of it, whatever the statement's shape, until an analysis had it
  planned again, as reading a page costs less than descending any index. The statements are written
  so that, with them off, a plan reaches its rows by key, by the group, the principal, the scope or
  the id the indexes lead to, whatever the statistics: statistics from a near-empty table count
  every value as distinct, so an index leading to the tenant looks as few rows to read by the tenant
  alone as by a key, and a plan for rows sorted in a table's order reads a whole index in that
  order. A plan made while the tables were small read 3,680 pages of grants, 7,546 of places and
  5,772 of eligibilities to delete one group beside 20,000 of each, and `Reachable` 18,744 of
  grants; beside 40,000 custom roles of other tenants, `Explain` and `CustomRoles` read 817 pages of
  them, and `Activate` 1,634. No index finds whom denies exempt and eligibilities name as approvers
  across tenants, so `DeletePrincipalEverywhere` reads every row of both, by a range of every row's
  `ctid`, a page at a time in the table's order, which sequential scans being off doesn't plan away:
  with them off and no such range, or TID scans off too, a plan read each through a whole index, in
  its order, ten times the pages the table holds. The statement deleting a group is planned so too,
  and with it the foreign key's cascade to its places, which PostgreSQL plans as the first deletion
  in a session runs it and keeps: a host's own deletion of a group, planned with sequential scans on
  while the places were few, leaves a plan that reads every one. `Filter`'s condition runs in the
  host's statement, which the host plans (Lists).
- **Expiry:** expired grants give nothing at once; `DeleteExpired` clears them a batch at a time,
  to run on a schedule, passing over what a change holds until the next run. A call reads
  `Config.Now` once, which every expiry it compares and every condition's `request.time` read, so a
  grant or a membership ending as it runs can't meet a deny, a condition or label values of a later
  moment; a change reads it again once it holds every lock it waits for, where it decides again:
  read before a wait, as for an `Activate` holding the places a change ends, it would decide at a
  time the wait left behind, as by an actor's power that ended while it waited. So a change holds
  first what it writes that `DeleteExpired`, which waits for nothing, may be deleting, and holds
  until its own transaction ends; and reads what its actor acts by in one statement with the denies
  binding it and its label values, as `SetRole` and `DeleteRole` do under the tenant's lock.
  `DeleteExpired` removes what has ended in transactions of its own, places in groups before
  memberships, passing over what a change holds, by its own clock: a read by an earlier clock could
  find the place a deny binds the actor by, which ended later, removed, and the membership or place
  its power comes through, which ended sooner, still there, a state no moment held. So each batch
  records in `rbac_expired`, in its own transaction, the latest time a row it removes ended at, a
  membership's for the places it removes with one, which ended by the run's `Config.Now` and the
  database's clock both: a host whose clock runs
  ahead, or a `Config.Now` set wrong, can't have a later call decide past the database's clock, and
  a run that removes nothing records nothing. It records it through `rbac_expired_through`, which
  deletes the times no later than its own and adds its own, refusing one past the database's clock,
  and history records each write, as one of the package's tables (History). So a role that may
  execute the function, as the application's may, can move what a call decides no earlier than up to
  that clock and no further, as a run could, and never back, and history records each time it wrote.
  A read that finds the latest time past the database's clock, as it reads the clock once it has its
  snapshot, decides neither at that time nor at the clock, but is refused (`rbac.ErrConflict`), a
  check and a list too, and `Filter`'s condition keeps no row: decided at that time, it would lift a
  deny binding through a place that ends before then, and meet a condition reading `request.time`,
  and decided at the clock, find the place a deny binds by, which a run removed, gone, and the
  membership or place a power comes through, which ended sooner and the run passed over, still
  there, a state no moment held. On a primary whose clock doesn't go back, no read is refused so: no
  write records a time past the clock as its own statement began, which is before it commits, and so
  before a read that sees it takes its snapshot. Compared with the clock as the read's statement
  began, a statement sent in a simple query, as by a pool that prepares none, which takes its
  snapshot once it is planned, after any lock it waited for, could find a time a run recorded after
  that, and be refused. A time is past the clock on a hot standby whose clock is behind its
  primary's, which replays what a run on the primary recorded, where the database's clock has gone
  back since a run recorded it, or where a role that may disable the table's triggers wrote it:
  there every check, list and change that reads it is refused until the clock passes the time, and
  from then on decides at it, as before. The comparison has no margin for the clocks' drift: however
  little the clock is behind the time, a row the run passed over could have ended between them. Keep
  the database's clock from stepping back, and a standby's synchronized with its primary's, or make
  checks, and run `Filter`'s conditions, on the primary. A time a run recorded while the database's
  clock was set far ahead, which then went back, refuses every call reading it until the clock
  passes it again. The table's owner can bring it back to the clock, as migrating to
  `0032_expired_writes` did, which history records, but reads then decide by the state the run left
  until the clock passes the time: what the run removed that hadn't ended by the clock, as the place
  a deny binds a subject by, gone, and what it passed over still there, a state no moment held. So
  first restore what the run removed that hadn't ended by the clock, which history records with each
  row, or wait for the clock. `AsOf`, which doesn't read the table, reads on a standby as before.
  A read of an actor's or a subject's grants, groups and
  the denies binding it, as `Authorize`, `Explain`, `Permissions`, `Grantable`, `Holding`,
  `Reachable` and every change make, `Holders`' snapshot, and the condition `Filter` gives the
  host, decides no earlier than the latest time recorded that its snapshot sees: every row it finds
  removed had ended by then, as it commits with the time, or is a place of an identity whose
  membership had, which gives nothing once it has. The call decides at that time from then
  on, its conditions' `request.time` and its statements after the read too. So a call decides later
  than its own clock only where a run removed a row that ended after it. A change is tried again
  instead (`rbac.ErrConflict`) where its transaction read the time before that read, as for whether
  what it grants to stands, or where, as its last statement finds, a run that committed after that
  read removed a row that ended after the change's time, which a statement after it, as the check
  of an exclusive dimension, could have found removed. Tried again, it finds the time before its
  transaction, and decides there no earlier, so it is refused again only where yet another run
  removes so while it runs: with `DeleteExpired` every 50 ms beside four sessions granting, without
  pause, roles that end 200 ms on, none of about 1,650 changes was tried again. `Filter`'s condition
  with the label column, whose holding the query doesn't read, keeps no row where the query sees a
  time as late as the first after `Filter` read the holding that the subject's keys change by time
  alone, as its membership, or its last path to one of its groups, ends: build it again. A place
  that ends while another, from another source or through another group, keeps it in the group
  changes none of them. Before then, the subject's
  keys and the denies binding it are those of `Filter`'s time, and the grants in force no more, so
  each row the query keeps the subject could read at `Filter`'s time; a run by an earlier time, as
  every one is for a subject whose membership and places don't end, leaves them as they were.
  `Members`, `GroupsOf`, `Memberships`, `MembershipsOf` and `Conflicts` read by the call's time:
  what each lists only grows with the rows in force, so each element it lists was in force at that
  time, and each it leaves out had ended by it or by a run's time. Runs never wait for each other,
  and a run removing what ended sooner leaves the latest time as it is. Keep the hosts' clocks
  synchronized with the database's: a host whose clock runs behind has a call after another's run
  that removed a row ending after its clock decide later than it reads. An activation still ends
  its duration after the time `Activate` read once it held the places it rests on, never later. As
  of a time, a read decides at that time.
  `SetMemberships` doesn't wait for the places in groups of a membership that ended while it took
  its locks, which another transaction holds, as a group's deletion: it is tried again
  (`rbac.ErrConflict`), as is a change whose host's clock goes back between the two readings.

## Development

`make check` runs every linter and test. The tests need a PostgreSQL database they may create
schemas in, named by `RBAC_TEST_DATABASE_URL`; without it they are skipped. CI runs them in shards,
each running its own top-level tests whole, and `make test SHARD=i/n` runs one; see
[CONTRIBUTING.md](CONTRIBUTING.md).
