# rbac

Role-based access control on PostgreSQL, as a Go library.

```sh
go get github.com/parallelworks/rbac
```

It needs Go 1.26 or later and is tested on PostgreSQL 18. It runs in FIPS 140-3 mode: it uses no
cryptography outside the Go standard library.

`rbac` is Core RBAC with scoped role assignments, on PostgreSQL. A role is a
set of `type:verb` permissions; a grant gives one role to a principal (a user,
another kind of identity the application declares, such as a service account,
a group, every member of the tenant, or the public) on a resource, a container
above resources (any depth, any names) or the tenant, and applies to
everything under it. The application keeps identities, groups, resources and
their hierarchy and passes them in; the package keeps only the grants, so
nothing it holds goes stale when someone leaves a group or a resource moves.

```go
authz, err := rbac.New(pool, rbac.Config{
	Catalog:           roles, // []rbac.RoleDefinition, built into the application
	ContainerTypes:    []string{"org", "workspace"},
	PrincipalKinds:    []rbac.PrincipalKind{"service_account"},
	ValidatePrincipal: members.InTenant, // required
	OnChange:          audit.Record,     // runs in the change's transaction
})

user := rbac.Principal{Kind: rbac.User, ID: userID}
subject := rbac.Subject{Principal: user, Groups: groupIDs, Tenants: []string{tenant}}
cluster := rbac.Resource{Tenant: tenant, Type: "cluster", ID: id,
	Ancestors: []rbac.Scope{{Type: "workspace", ID: ws}, {Type: "org", ID: org}}}
if err := authz.Authorize(ctx, subject, "cluster:login", cluster); err != nil {
	return err // matches rbac.ErrDenied; any error means no
}
```

- **Lists:** store each resource's `authz.Path(resource)` in a `text[]`
  column with a GIN index, and `Filter` returns a condition for the
  application's own query, read in the same statement as the rows.
  `Reachable` returns the same as scopes, for resources kept in another
  store. Both search one tenant.
- **Creators:** nothing is owned. Give whoever creates a resource or a
  container a role on it with `Import`, in the same transaction through
  `WithTx`. Every ancestor must be of a declared container type.
- **Changes:** `Apply` changes one scope's grants in one transaction, one
  change to a scope at a time. The actor needs `<type>:grant` there. Through
  a role with `GrantableRoles` it may grant and revoke only those roles,
  without holding them; through any other, it may grant a role whose every
  permission it holds, for every type the grant reaches, and revoke any. A
  role's power to change grants counts as part of what it gives: granting one
  with `GrantableRoles` takes the power to grant each listed role its holders
  could, and one without takes the unlimited power on its type. `Grantable`
  lists the roles a subject may grant, for an access screen. A grant outlives
  the actor's own access, so a time-limited power to change grants can make
  lasting ones: put expiries on roles that can't change grants. `Import` loads
  grants for migrations.
- **Custom roles:** a tenant defines its own with `DefineRole`, ids starting
  `custom.`, from the permissions and types the built-in roles use; a public
  one only from what a role that isn't privileged gives on each of its types.
  Defining one needs `rbac.DefineRoles` on the tenant and everything the role
  gives across it, as the actor's roles give now; replacing one changes what
  its grants give, and replacing one another custom role lists needs the
  power to grant it where that role does. `DeleteRole` removes one with its
  grants. `RolesIn` lists the built-in and custom roles a scope type takes. A
  tenant has up to 300, each listing up to 64 grantable roles, and they follow
  the catalog: one gives only what the catalog still has, and is privileged
  when it gives or hands out what privileged roles do.
- **Conditions:** a grant can carry a CEL expression over the subject's, the
  resource's and the request's attributes (`Subject.Attributes`,
  `Resource.Attributes`, `rbac.WithRequest`), the time and the action, such as
  only dev resources or only with a second factor. It gives its role only
  where the expression holds; one that fails is false. A check reads
  conditions only when no unconditional grant allows. Searches count
  unconditional grants, and `Reach.Conditional` names the scopes conditional
  ones reach, to check one by one. To hand a permission or the power to change
  grants on, the actor holds it unconditionally or under the same condition,
  and a conditional power to change grants holds only when its condition does:
  a role a conditional grant lists is granted only under its condition. A
  pattern a condition matches is a string literal of bounded size, and a
  condition's title and description are at most 128 and 2048 bytes.
- **Deny policies:** `SetDeny` puts a deny on a scope: under it, it removes
  permissions (`type:verb`, or `type:*` for a type's every one) from the
  principals it names, those it exempts aside, whatever their grants give. A
  conditional one denies where its condition holds or can't be evaluated.
  Setting one needs `rbac.DenyPermission(type)` there, which no deny
  removes, so whoever holds it on a scope above can always lift a deny set
  below, and whoever holds it on the deny's own scope, those it names
  included, can lift that deny: to bind one who holds it, set the deny on a
  scope above. A check reads denies with grants in one statement. What a
  deny on a change's path removes from the actor isn't held to hand on, nor,
  through a container or the tenant, what one whose condition reads the
  resource may remove; a deny on a scope below the change's isn't read.
  `Filter` leaves out what a deny covers, `Reachable` names it in `Except`,
  conditional ones in `ConditionalExcept`, and `Holders` leaves out those a
  deny names. A deny read back says who created it and who last changed it.
- **Eligible grants:** `SetEligible` lets a principal, an identity or a
  group's members, activate a role on a scope for up to a maximum duration and
  no later than the eligibility ends, perhaps only where a condition holds,
  such as a second factor; setting one takes what granting the role would.
  `Activate` gives the identity activating the role until then, with its
  justification as the grant's note, reported in `ChangeEvent.Granted` with
  `Activated` set. An approval before activating is the host's. Every grant
  can carry a `Note`.
- **Identities:** an identity's or group's id names it in every tenant, so a
  tenant can grant a role to one from another where `ValidatePrincipal`
  allows it; `Subject.Tenants` decides only which tenants' members it is.
  `DeletePrincipalEverywhere` removes a deleted identity's grants.
- **Public access:** the zero `Subject` is anonymous and holds only what is
  granted to the public (`rbac.Principal{Kind: rbac.Public}`). Only a role
  marked `Public` can be granted to the public, and a grant to the public
  gives nothing once its role no longer is. `ValidatePrincipal` is asked
  about the public, so an application can refuse public access in a tenant;
  `DeletePrincipal` ends what was granted.
- **Broad grants:** a grant to the tenant's members (`rbac.TenantMembers`) or
  the public never gives a `<type>:grant` or `<type>:deny` permission or
  `rbac.DefineRoles`, so changing access always takes a named identity or
  group.
- **Why:** `Explain` names the grants that allow, or what denied;
  `Permissions` lists what a subject may do; `Holders` lists who may.
- **Tables:** `rbac.Migrate` creates them, prefixed `rbac_`, in the
  connection's current schema, and records what it applied in
  `rbac_migrations`. It never runs by itself; a host with a migration tool of
  its own can apply `rbac.Migrations()` instead.

No decision is cached, only compiled conditions: a check is one index-only
query, and another when a grant it reads names a custom role or needs its
condition read. Read a resource's path and attributes and a subject's groups no
earlier than the content they protect, and from the primary, so a revocation is
never missed. Groups taken from a token stay valid until it expires.
`DeleteExpired` clears expired grants, which already give nothing.

## Development

`make check` runs every linter and test. The tests need a PostgreSQL database they may create
schemas in, named by `RBAC_TEST_DATABASE_URL`; without it they are skipped. See
[CONTRIBUTING.md](CONTRIBUTING.md).
