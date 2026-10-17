# rbac

Role-based access control on PostgreSQL, as a Go library: roles granted on resources, the
containers above them or a whole tenant, with custom roles, conditions, deny policies and
just-in-time access, in the shape of cloud IAM.

```sh
go get github.com/parallelworks/rbac
```

It needs Go 1.26 or later and is tested on PostgreSQL 18. It runs in FIPS 140-3 mode: it uses no
cryptography outside the Go standard library.

## The model

A role is a set of `type:verb` permissions, such as `cluster:login`, built into the application's
catalog or defined by a tenant. A grant gives one role to a principal on a scope, and applies to
everything under it: a resource, a container above resources (any depth, any names), or the
tenant. A principal is a user, another kind of identity the application declares (a service
account), a group, every member of the tenant, or the public, signed in or not.

The application keeps identities, groups, resources and their hierarchy, and passes them in: a
`Subject` is an identity with its groups and tenants, and a `Resource` carries its ancestors. The
package keeps only grants and its own policies, so nothing it holds goes stale when someone
leaves a group or a resource moves.

```go
authz, err := rbac.New(pool, rbac.Config{
	Catalog:        roles, // []rbac.RoleDefinition, built into the application
	ContainerTypes: []string{"org", "workspace"},
	PrincipalKinds: []rbac.PrincipalKind{"service_account"},
	ValidateGrant:  policy.MayGrant, // required: who may hold what in a tenant
	OnChange:       audit.Record,    // runs in the change's transaction
})

subject := rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: userID}, Groups: groupIDs, Tenants: []string{tenant}}
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
  grants them from a `Source` of its own and revokes only those.
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
query, which reads the grants in the same statement as the rows, so sorting and pagination work
and nothing changes between deciding and reading. A subject's grants on resources of the listed
type are looked up by each row's own key, so one holding a grant on everything it created lists
as fast as one holding a few. `Reachable` returns the same as scopes, for resources kept in
another store. Both search one tenant, and count only unconditional grants:
`Reach.Conditional` names the scopes conditional ones reach, to check one by one.

## Policies

- **Custom roles:** a tenant defines its own with `SetRole`, ids starting `custom.`, from the
  permissions and types the built-in roles use. Defining one needs `rbac.DefineRoles` on the
  tenant and everything the role gives across it. `DeleteRole` removes one with its grants;
  `Roles` lists the built-in and custom roles a scope type takes. Custom roles follow the
  catalog: one gives only what the catalog still has, and is privileged when it gives or hands out
  what privileged roles do.
- **Conditions:** a grant can carry a CEL expression over the subject's, the resource's and the
  request's attributes (`Subject.Attributes`, `Resource.Attributes`, `rbac.WithRequest`), the time
  and the action. It gives its role only where the expression holds; one that fails is false.
  `Config.Attributes` declares the attributes and their types, so a condition reading one
  misnamed, or as another type, is refused when stored. Cost is bounded per condition and per
  check. To hand a permission on, the actor holds it unconditionally or under the same condition.
- **Deny policies:** `SetDeny` puts a deny on a scope: under it, it removes permissions
  (`type:verb`, or `type:*` for a type's every one) from the principals it names, those it exempts
  aside, whatever their grants give. A conditional one denies where its condition holds or can't
  be evaluated. Setting one needs `rbac.DenyPermission(type)` there, which no deny removes, so
  whoever holds it on a scope above can always lift a deny set below. `Filter`, `Reachable` and
  `Holders` honor denies.
- **Just-in-time access:** `SetEligibility` lets a principal, an identity or a group's members,
  activate a role on a scope for up to a maximum duration and no later than the eligibility ends,
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
  changes under a container.

## Principals

- **Identities across tenants:** an identity's or group's id names it in every tenant, so a tenant
  can grant a role to one from another where `ValidateGrant` allows it; `Subject.Tenants` decides
  only which tenants' members it is. `DeletePrincipalEverywhere` removes a deleted identity's
  grants.
- **Public access:** the zero `Subject` is anonymous and holds only what is granted to the public.
  Only a role marked `Public` can be granted to the public, and a grant to the public gives
  nothing once its role no longer is.
- **Broad grants:** a grant to a tenant's members (`rbac.TenantMembers`) or the public never gives
  a `<type>:grant` or `<type>:deny` permission or `rbac.DefineRoles`, so changing access always
  takes a named identity or group.

## Why

`Explain` names the grants that allow, or the deny or constraint that denied; `Permissions` lists
what a subject may do; `Holders` lists who may. A `DeniedError`'s message names only the
permission, so an error shown to a user shows no policy; its fields say why.

## Running it

- **Tables:** `rbac.Migrate` creates them, prefixed `rbac_`, in the connection's current schema,
  and records what it applied in `rbac_migrations`. It never runs by itself; a host with a
  migration tool of its own can apply `rbac.Migrations()` instead.
- **Transactions:** a change runs in its own transaction at READ COMMITTED, or under `WithTx` in
  the host's, which must be READ COMMITTED too. A change refused for a race, such as a deadlock
  between host transactions, matches `rbac.ErrConflict`: try it again.
- **What the host passes:** a check reads grants as they are; only compiled conditions are cached.
  Read a resource's ancestors and attributes and a subject's groups from where they are stored,
  never from request input, no earlier than the content they protect, and from the primary. A
  deny is only as complete as the groups and ancestors passed: one naming a group binds only
  subjects passed with it.
- **Ids:** an id names its identity, group or resource for good. Never reuse one, or a new
  resource or account inherits the grants of the one before it. Delete a resource's grants with
  `DeleteScope` in the transaction that deletes it, for each scope under it too, and rewrite the
  stored paths below a container when it moves.
- **Limits:** a change takes at most `rbac.MaxBindings` bindings; a principal holds a role on a
  scope at most `rbac.MaxGrantsPerRole` times; a scope holds at most `rbac.MaxDenies` denies; a
  tenant has at most `rbac.MaxCustomRoles` custom roles. The others are exported beside them.
- **Expiry:** expired grants give nothing at once; `DeleteExpired` clears them, to run on a
  schedule.

## Development

`make check` runs every linter and test. The tests need a PostgreSQL database they may create
schemas in, named by `RBAC_TEST_DATABASE_URL`; without it they are skipped. See
[CONTRIBUTING.md](CONTRIBUTING.md).
