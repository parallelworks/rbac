package rbac_test

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/parallelworks/rbac"
	"github.com/parallelworks/rbac/internal/pgtest"
)

// granter changes grants on clusters, holding nothing it hands on; lister grants cluster.sudo
// without holding it.
var (
	granter = rbac.RoleDefinition{ID: "cluster.granter", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, Privileged: true}
	lister  = rbac.RoleDefinition{
		ID: "cluster.lister", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, Privileged: true,
		GrantableRoles: []rbac.Role{"cluster.sudo"},
	}
)

func TestAConditionReadingTheSubjectIsNoAuthorityToHandItOn(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), granter, lister) })
	ctx := t.Context()
	carolOnly := rbac.Condition{Expression: `subject.id == "carol"`}
	mfa := rbac.Condition{Expression: `request.attributes.mfa == true`}
	held := func(role rbac.Role, id string, c rbac.Condition) rbac.Grant {
		g := grant(cluster.Scope(), role, rbac.User, id)
		g.Condition = c
		return g
	}
	// bob holds sudo only where the subject is carol, which he never is; lee may grant sudo there
	// only on the same terms.
	h.seed(t, grant(cluster.Scope(), "cluster.granter", rbac.User, "bob"), held("cluster.sudo", "bob", carolOnly),
		held("cluster.lister", "lee", carolOnly), grant(cluster.Scope(), "cluster.granter", rbac.User, "max"), held("cluster.sudo", "max", mfa))
	h.join(t, "carol")
	toCarol := func(c rbac.Condition) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: identity("carol"), Condition: c}}}
	}
	mfaCtx := rbac.WithRequest(ctx, map[string]any{"mfa": true})
	for name, actor := range map[string]rbac.Subject{"held": h.as(t, "bob"), "listed": h.as(t, "lee")} {
		if err := h.authz.Apply(mfaCtx, actor, cluster, toCarol(carolOnly)); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s under a condition on the subject, handed on under it: %v", name, err)
		}
	}
	// Named from the root, it reads the subject all the same.
	rooted := rbac.Condition{Expression: `.subject.id == "carol"`}
	h.seed(t, held("cluster.sudo", "ray", rooted), grant(cluster.Scope(), "cluster.granter", rbac.User, "ray"))
	if err := h.authz.Apply(mfaCtx, h.as(t, "ray"), cluster, toCarol(rooted)); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("held under a condition on the subject named from the root, handed on under it: %v", err)
	}
	// A condition on the request is the same for whoever is granted it.
	if err := h.authz.Apply(mfaCtx, h.as(t, "max"), cluster, toCarol(mfa)); err != nil {
		t.Fatalf("held under a condition on the request, handed on under it: %v", err)
	}
}

func TestAnActivationLastsNoLongerThanThePlaceThatMakesItsSubjectEligible(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "oncall"}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("oncall"), MaxDuration: 300 * 24 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "oncall", Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	u := h.as(t, "u", "oncall")
	act := func(d time.Duration) error {
		_, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: d, Justification: "INC-1"})
		return err
	}
	if err := act(30 * 24 * time.Hour); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("an activation outlasting the place in the group: %v", err)
	}
	if err := act(30 * time.Minute); err != nil {
		t.Fatalf("one ending before it: %v", err)
	}
}

// lastEvent is the last change h reported, failing t where it reported none.
func lastEvent(t *testing.T, h *harness) rbac.ChangeEvent {
	t.Helper()
	if len(h.events) == 0 {
		t.Fatal("no change was reported")
	}
	return h.events[len(h.events)-1]
}

// activatedThroughOncall is grouped with u in oncall, or in inner, which is in oncall, and an
// activation of sudo on the cluster for eight hours, which u is eligible for through oncall.
func activatedThroughOncall(t *testing.T, nested bool) (*harness, rbac.Subject, rbac.Grant) {
	t.Helper()
	h := grouped(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
	ctx := t.Context()
	h.groups(t, "oncall", "inner", "team")
	u := h.as(t, "u", "oncall")
	if nested {
		u = h.as(t, "u", "inner")
		if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "oncall", Principal: groupOf("inner")}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("oncall"), MaxDuration: 8 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	g, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 8 * time.Hour, Justification: "incident"})
	if err != nil {
		t.Fatal(err)
	}
	return h, u, g
}

// An activation lasts no longer than the place in a group, or the membership, it rests on: ending
// one sooner cuts it short to then, and removing one ends it, through whichever change does.
func TestEndingAPlaceOrMembershipEndsTheActivationsRestingOnIt(t *testing.T) {
	soon := func(h *harness) time.Time { return h.now.Add(time.Minute) }
	for name, c := range map[string]struct {
		nested, sooner bool
		end            func(t *testing.T, h *harness) error
	}{
		"ChangeMembers removing it": {end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.ChangeMembers(t.Context(), h.as(t, "manager"), "t1", nil, []rbac.Member{{Group: "oncall", Principal: identity("u")}})
		}},
		"ChangeMembers ending it sooner": {sooner: true, end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.ChangeMembers(t.Context(), h.as(t, "manager"), "t1", []rbac.Member{{Group: "oncall", Principal: identity("u"), ExpiresAt: soon(h)}}, nil)
		}},
		"DeleteMembers": {end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.DeleteMembers(t.Context(), host, "t1", []rbac.Member{{Group: "oncall", Principal: identity("u")}})
		}},
		"ImportMembers ending it sooner": {sooner: true, end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.ImportMembers(t.Context(), host, "t1", []rbac.Member{{Group: "oncall", Principal: identity("u"), ExpiresAt: soon(h)}})
		}},
		"SetMemberships ending the membership sooner": {sooner: true, end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.SetMemberships(t.Context(), host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: soon(h)}})
		}},
		"ImportGroups taking the group over": {end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.ImportGroups(t.Context(), host, "t1", []rbac.GroupDefinition{{ID: "oncall", Source: "directory"}})
		}},
		"DeleteGroups": {end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.DeleteGroups(t.Context(), host, "t1", []string{"oncall"})
		}},
		"ChangeMembers removing the group it is in": {nested: true, end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.ChangeMembers(t.Context(), h.as(t, "manager"), "t1", nil, []rbac.Member{{Group: "oncall", Principal: groupOf("inner")}})
		}},
		"ChangeMembers ending the place of the group it is in sooner": {nested: true, sooner: true, end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.ChangeMembers(t.Context(), h.as(t, "manager"), "t1", []rbac.Member{{Group: "oncall", Principal: groupOf("inner"), ExpiresAt: soon(h)}}, nil)
		}},
		"DeletePrincipal of the group it is in": {nested: true, end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.DeletePrincipal(t.Context(), host, "t1", groupOf("inner"))
		}},
		"DeleteGroups of the group it is in": {nested: true, end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.DeleteGroups(t.Context(), host, "t1", []string{"inner"})
		}},
	} {
		t.Run(name, func(t *testing.T) {
			h, u, g := activatedThroughOncall(t, c.nested)
			h.events = nil
			ends := soon(h)
			if err := c.end(t, h); err != nil {
				t.Fatal(err)
			}
			e := lastEvent(t, h)
			reported := e.Revoked
			if c.sooner {
				reported = e.Shortened
			}
			if !slices.ContainsFunc(reported, func(r rbac.Grant) bool { return r.ID == g.ID && (!c.sooner || r.ExpiresAt.Equal(ends)) }) {
				t.Errorf("the activation isn't reported cut short or ended: %+v", e)
			}
			h.now = h.now.Add(30 * time.Second)
			if allowed(t, h, u, root, cluster) != c.sooner {
				t.Errorf("u holds sudo until what it rests on ends: %v", !c.sooner)
			}
			h.now = h.now.Add(time.Hour)
			if allowed(t, h, u, root, cluster) {
				t.Error("u holds sudo past the end of the place it activated it through")
			}
		})
	}
}

// Ending a place or a membership ends only the activations resting on it: one made through another
// group, or through the identity's own eligibility, lasts, as does one whose group the change leaves
// its holder in, and one whose eligibility was deleted or set to end sooner, which that left to its
// own end, when its holder leaves another group.
func TestEndingAPlaceLeavesTheActivationsItDoesntAllow(t *testing.T) {
	leave := func(group string) func(t *testing.T, h *harness) error {
		return func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.ChangeMembers(t.Context(), h.as(t, "manager"), "t1", nil, []rbac.Member{{Group: group, Principal: identity("u")}})
		}
	}
	eligible := func(t *testing.T, h *harness, e rbac.Eligibility) {
		t.Helper()
		e.Role, e.MaxDuration = "cluster.sudo", 8*time.Hour
		if err := h.authz.SetEligibility(t.Context(), h.as(t, "owner"), cluster, e); err != nil {
			t.Fatal(err)
		}
	}
	for name, c := range map[string]struct {
		// made sets up what u activates through, and returns u and whoever approves.
		made func(t *testing.T, h *harness) (u, approver rbac.Subject)
		// before changes what u activated, once it has.
		before func(t *testing.T, h *harness) error
		end    func(t *testing.T, h *harness) error
	}{
		"made through another group": {made: func(t *testing.T, h *harness) (rbac.Subject, rbac.Subject) {
			t.Helper()
			eligible(t, h, rbac.Eligibility{Principal: groupOf("team")})
			return h.as(t, "u", "oncall", "team"), rbac.Subject{}
		}, end: leave("oncall")},
		"made through its own eligibility": {made: func(t *testing.T, h *harness) (rbac.Subject, rbac.Subject) {
			t.Helper()
			eligible(t, h, rbac.Eligibility{Principal: identity("u")})
			return h.as(t, "u", "oncall"), rbac.Subject{}
		}, end: leave("oncall")},
		// Setting the eligibility to end sooner, or deleting it, left the activation to its end,
		// which leaving a group it doesn't rest on changes nothing of.
		"its eligibility ends sooner, and it leaves another group": {made: func(t *testing.T, h *harness) (rbac.Subject, rbac.Subject) {
			t.Helper()
			eligible(t, h, rbac.Eligibility{Principal: groupOf("oncall")})
			return h.as(t, "u", "oncall", "team"), rbac.Subject{}
		}, before: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.SetEligibility(t.Context(), h.as(t, "owner"), cluster, rbac.Eligibility{
				Role: "cluster.sudo", Principal: groupOf("oncall"), MaxDuration: 8 * time.Hour, ExpiresAt: h.now.Add(2 * time.Hour),
			})
		}, end: leave("team")},
		"its eligibility was deleted, and it leaves another group": {made: func(t *testing.T, h *harness) (rbac.Subject, rbac.Subject) {
			t.Helper()
			eligible(t, h, rbac.Eligibility{Principal: groupOf("oncall")})
			return h.as(t, "u", "oncall", "team"), rbac.Subject{}
		}, before: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.DeleteEligibility(t.Context(), h.as(t, "owner"), cluster, "cluster.sudo", groupOf("oncall"))
		}, end: leave("team")},
		// Deleting a group as a principal deletes its eligibilities and its places in other groups,
		// and leaves its members in it, which the activation made through it rests on.
		"the group it was made through keeps its members": {made: func(t *testing.T, h *harness) (rbac.Subject, rbac.Subject) {
			t.Helper()
			if err := h.authz.ImportMembers(t.Context(), host, "t1", []rbac.Member{{Group: "oncall", Principal: groupOf("inner")}}); err != nil {
				t.Fatal(err)
			}
			eligible(t, h, rbac.Eligibility{Principal: groupOf("inner")})
			return h.as(t, "u", "inner"), rbac.Subject{}
		}, end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.DeletePrincipal(t.Context(), host, "t1", groupOf("inner"))
		}},
		// Deleting a group deletes the eligibilities only it approves, and the activation made through
		// one rests on the identity alone.
		"made through an eligibility only the deleted group approves": {made: func(t *testing.T, h *harness) (rbac.Subject, rbac.Subject) {
			t.Helper()
			eligible(t, h, rbac.Eligibility{Principal: identity("u"), Approvers: []rbac.Principal{groupOf("oncall")}})
			return h.as(t, "u", "oncall"), h.as(t, "boss", "oncall")
		}, end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.DeleteGroups(t.Context(), host, "t1", []string{"oncall"})
		}},
	} {
		t.Run(name, func(t *testing.T) {
			h := grouped(t)
			h.groups(t, "oncall", "inner", "team")
			u, approver := c.made(t, h)
			g, err := h.authz.Activate(t.Context(), u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 8 * time.Hour, Justification: "incident", Approver: approver})
			if err != nil {
				t.Fatal(err)
			}
			if c.before != nil {
				if err := c.before(t, h); err != nil {
					t.Fatal(err)
				}
			}
			if err := c.end(t, h); err != nil {
				t.Fatal(err)
			}
			h.now = h.now.Add(time.Hour)
			if !allowed(t, h, u, root, cluster) {
				t.Error("ending a place ended an activation that doesn't rest on it")
			}
			if got, err := h.authz.Grants(t.Context(), "t1", rbac.GrantFilter{Principals: []rbac.Principal{u.Principal}}); err != nil || len(got) != 1 || !got[0].ExpiresAt.Equal(g.ExpiresAt) {
				t.Fatalf("Grants = %+v, %v", got, err)
			}
		})
	}
}

// An activation rests on the group it was made through, whatever else would allow one: leaving the
// group ends it though another group, or the identity's own eligibility, would allow it for as long
// or for an hour, or its eligibility was deleted, which left it to its end only while the place it
// rests on lasts.
func TestEndingThePlaceAnActivationWasMadeThroughEndsItWhateverElseAllows(t *testing.T) {
	leave := func(t *testing.T, h *harness) error {
		t.Helper()
		return h.authz.ChangeMembers(t.Context(), h.as(t, "manager"), "t1", nil, []rbac.Member{{Group: "oncall", Principal: identity("u")}})
	}
	eligible := func(p rbac.Principal, d time.Duration) func(t *testing.T, h *harness) error {
		return func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.SetEligibility(t.Context(), h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: p, MaxDuration: d})
		}
	}
	for name, c := range map[string]struct {
		nested bool
		before func(t *testing.T, h *harness) error
		end    func(t *testing.T, h *harness) error
	}{
		"another group allows it":             {before: eligible(groupOf("team"), 8*time.Hour), end: leave},
		"another group allows it for an hour": {before: eligible(groupOf("team"), time.Hour), end: leave},
		"its own eligibility allows it":       {before: eligible(identity("u"), 8*time.Hour), end: leave},
		"its eligibility was deleted": {before: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.DeleteEligibility(t.Context(), h.as(t, "owner"), cluster, "cluster.sudo", groupOf("oncall"))
		}, end: leave},
		"the group it is in through, deleted as a principal, allows it": {nested: true, before: eligible(groupOf("inner"), 8*time.Hour), end: func(t *testing.T, h *harness) error {
			t.Helper()
			return h.authz.DeletePrincipal(t.Context(), host, "t1", groupOf("inner"))
		}},
	} {
		t.Run(name, func(t *testing.T) {
			h, u, g := activatedThroughOncall(t, c.nested)
			if !c.nested {
				u = h.as(t, "u", "oncall", "team")
			}
			if err := c.before(t, h); err != nil {
				t.Fatal(err)
			}
			h.events = nil
			if err := c.end(t, h); err != nil {
				t.Fatal(err)
			}
			if e := lastEvent(t, h); len(e.Shortened) != 0 || !slices.ContainsFunc(e.Revoked, func(r rbac.Grant) bool { return r.ID == g.ID }) {
				t.Errorf("the activation isn't reported ended: %+v", e)
			}
			if allowed(t, h, u, root, cluster) {
				t.Error("u holds sudo it activated through oncall once it is no longer in oncall")
			}
		})
	}
}

// An activation rests on the eligibility it was made through alone: one its holder could reach whose
// requirement it didn't meet, or that needs an approver it had none of, didn't allow it, and keeps
// nothing once it leaves the group it was made through.
func TestAnEligibilityAnActivationWasntMadeThroughDoesntKeepIt(t *testing.T) {
	for name, team := range map[string]rbac.Eligibility{
		"a requirement it didn't meet": {Requires: `request.attributes.mfa == true`},
		"an approver it had none of":   {Approvers: []rbac.Principal{identity("boss")}},
	} {
		t.Run(name, func(t *testing.T) {
			h := grouped(t)
			ctx := t.Context()
			h.groups(t, "oncall", "team")
			h.as(t, "boss")
			u := h.as(t, "u", "oncall", "team")
			team.Role, team.Principal, team.MaxDuration = "cluster.sudo", groupOf("team"), 8*time.Hour
			oncall := rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("oncall"), MaxDuration: 8 * time.Hour}
			for _, e := range []rbac.Eligibility{team, oncall} {
				if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 8 * time.Hour, Justification: "incident"}); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", nil, []rbac.Member{{Group: "oncall", Principal: u.Principal}}); err != nil {
				t.Fatal(err)
			}
			if allowed(t, h, u, root, cluster) {
				t.Error("u holds sudo through team's eligibility, which never allowed it")
			}
		})
	}
}

// Of the eligibilities that allow an activation, it is made through the one whose path from its
// holder lasts longest, activating again until later too: the identity's own, which lasts as long as
// its membership, or a group it is in for good over one it is in until a time, so leaving the other
// group keeps it. Of those lasting alike, the identity's own is chosen over a group's with a
// cheaper requirement, as the group's path rests on its membership too. Which eligibilities allow
// it is decided first: one needing an approver the activation has none of lasts no longer for
// being the identity's own.
func TestAnActivationIsMadeThroughThePathThatLastsLongest(t *testing.T) {
	for name, c := range map[string]struct {
		// first are the eligibilities u activates through first, and then those set before it
		// activates again until later, if any.
		first, then []rbac.Eligibility
		// oncall is when u's place in oncall ends, zero for never.
		oncall func(h *harness) time.Time
		kept   bool
	}{
		"its own over a group's": {first: []rbac.Eligibility{{Principal: groupOf("oncall")}, {Principal: identity("u")}}, kept: true},
		"its own needing a requirement it meets over a group's needing none": {
			first: []rbac.Eligibility{{Principal: groupOf("oncall")}, {Principal: identity("u"), Requires: `request.attributes.mfa == true`}}, kept: true,
		},
		"its own over a group's, activating again until later": {
			first: []rbac.Eligibility{{Principal: groupOf("oncall")}}, then: []rbac.Eligibility{{Principal: identity("u")}}, kept: true,
		},
		"a group it is in for good over one it is in for a while": {
			first:  []rbac.Eligibility{{Principal: groupOf("oncall")}, {Principal: groupOf("team")}},
			oncall: func(h *harness) time.Time { return h.now.Add(3 * time.Hour) }, kept: true,
		},
		"a group's over its own needing an approver it has none of": {
			first: []rbac.Eligibility{{Principal: groupOf("oncall")}, {Principal: identity("u"), Approvers: []rbac.Principal{identity("boss")}}},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := grouped(t)
			ctx := rbac.WithRequest(t.Context(), map[string]any{"mfa": true})
			h.groups(t, "oncall", "team")
			h.as(t, "boss")
			u := h.as(t, "u", "team")
			place := rbac.Member{Group: "oncall", Principal: identity("u")}
			if c.oncall != nil {
				place.ExpiresAt = c.oncall(h)
			}
			if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{place}); err != nil {
				t.Fatal(err)
			}
			activate := func(es []rbac.Eligibility, d time.Duration) {
				t.Helper()
				for _, e := range es {
					e.Role, e.MaxDuration = "cluster.sudo", 8*time.Hour
					if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: d, Justification: "incident"}); err != nil {
					t.Fatal(err)
				}
			}
			activate(c.first, time.Hour)
			if c.then != nil {
				activate(c.then, 2*time.Hour)
			}
			if err := h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "oncall", Principal: u.Principal}}); err != nil {
				t.Fatal(err)
			}
			if allowed(t, h, u, root, cluster) != c.kept {
				t.Errorf("u holds sudo once it left oncall: %v", !c.kept)
			}
		})
	}
}

// A path from an activation's holder lasts as long as the soonest of its membership and the places
// on it, and a principal's as the latest of the paths to it, through groups in groups too, so the
// activation is made through the eligibility whose principal's lasts longest, and leaving the place
// that leads to the other keeps it.
func TestAnActivationsPathLastsAsItsSoonestPlaceAndAPrincipalsAsItsLatestPath(t *testing.T) {
	type place struct {
		group     string
		principal rbac.Principal
		// ends is how long from now it lasts, zero for good.
		ends time.Duration
	}
	for name, c := range map[string]struct {
		// membership is how long u's membership lasts, zero for good.
		membership time.Duration
		places     []place
		eligible   []rbac.Principal
		leave      rbac.Member
	}{
		"a path through a place that ends": {
			places:   []place{{"inner", identity("u"), 3 * time.Hour}, {"oncall", groupOf("inner"), 0}, {"team", identity("u"), 0}},
			eligible: []rbac.Principal{groupOf("oncall"), groupOf("team")}, leave: rbac.Member{Group: "inner", Principal: identity("u")},
		},
		"a group's path through a membership that ends": {
			membership: 5 * time.Hour, places: []place{{"oncall", identity("u"), 0}},
			eligible: []rbac.Principal{groupOf("oncall"), identity("u")}, leave: rbac.Member{Group: "oncall", Principal: identity("u")},
		},
		"the latest of the paths to a group": {
			places: []place{
				{"oncall", identity("u"), 3 * time.Hour}, {"inner", identity("u"), 0}, {"oncall", groupOf("inner"), 0}, {"team", identity("u"), 4 * time.Hour},
			},
			eligible: []rbac.Principal{groupOf("oncall"), groupOf("team")}, leave: rbac.Member{Group: "team", Principal: identity("u")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := grouped(t)
			ctx := t.Context()
			h.groups(t, "oncall", "inner", "team")
			u := h.as(t, "u")
			if c.membership != 0 {
				if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: u.Principal, ExpiresAt: h.now.Add(c.membership)}}); err != nil {
					t.Fatal(err)
				}
			}
			var places []rbac.Member
			for _, p := range c.places {
				m := rbac.Member{Group: p.group, Principal: p.principal}
				if p.ends != 0 {
					m.ExpiresAt = h.now.Add(p.ends)
				}
				places = append(places, m)
			}
			if err := h.authz.ImportMembers(ctx, host, "t1", places); err != nil {
				t.Fatal(err)
			}
			for _, p := range c.eligible {
				e := rbac.Eligibility{Role: "cluster.sudo", Principal: p, MaxDuration: 8 * time.Hour}
				if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, e); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Hour, Justification: "incident"}); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{c.leave}); err != nil {
				t.Fatal(err)
			}
			if !allowed(t, h, u, root, cluster) {
				t.Errorf("u leaving %s ended the activation", c.leave.Group)
			}
		})
	}
}

// Ending one of the paths to the group an activation was made through cuts it short to the latest
// end of those left.
func TestEndingAPathCutsAnActivationToTheLatestLeft(t *testing.T) {
	h, _, g := activatedThroughOncall(t, false)
	ctx := t.Context()
	u := h.as(t, "u", "oncall", "inner")
	ends := h.now.Add(2 * time.Hour)
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "oncall", Principal: groupOf("inner"), ExpiresAt: h.now.Add(time.Hour)},
		{Group: "team", Principal: identity("u")},
		{Group: "oncall", Principal: groupOf("team"), ExpiresAt: ends},
	}); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", nil, []rbac.Member{{Group: "oncall", Principal: u.Principal}}); err != nil {
		t.Fatal(err)
	}
	if e := lastEvent(t, h); len(e.Shortened) != 1 || e.Shortened[0].ID != g.ID || !e.Shortened[0].ExpiresAt.Equal(ends) {
		t.Errorf("the activation isn't reported cut short to when u's place through team ends: %+v", e)
	}
	h.now = h.now.Add(90 * time.Minute)
	if !allowed(t, h, u, root, cluster) {
		t.Error("u lost sudo while in oncall through team")
	}
	h.now = ends
	if allowed(t, h, u, root, cluster) {
		t.Error("u holds sudo past its last path to oncall")
	}
}

// Activate, a change ending places an activation rests on, and a change reading when its actor's
// paths end, walk up on the latest path to each group alone, so their walks make rows about as many
// as the places they walk, however the groups converge and fan out again: walking on from every
// end, each group past a fan-out is walked once for every end converging before it, and layers of a
// few hundred groups make millions of rows, read for seconds under the change's locks. The
// activation lasts, and is cut short to, the latest of its paths all the same.
func TestWalkingUpLayeredGroupsWalksTheLatestPathToEachAlone(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	const n = 40
	// u is in n groups x_i, its place in each ending a minute after the one before; each is in y,
	// which is in n groups z_i, each in w, which is in n groups v_i, each in q. Written around the
	// hooks, as a large tenant's are.
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id) VALUES ('t1', 'user', 'u')`, nil},
		{`INSERT INTO rbac_groups (tenant, id) SELECT 't1', unnest(ARRAY['y', 'w', 'q'])
		  UNION ALL SELECT 't1', l || i FROM unnest(ARRAY['x', 'z', 'v']) l, generate_series(1, $1) i`, []any{n}},
		{`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id, expires_at)
		  SELECT 't1', 'x' || i, 'user', 'u', $2::timestamptz + i * interval '1 minute' FROM generate_series(1, $1) i`, []any{n, h.now.Add(time.Hour)}},
		{`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		  SELECT 't1', 'y', 'group', 'x' || i FROM generate_series(1, $1) i
		  UNION ALL SELECT 't1', 'z' || i, 'group', 'y' FROM generate_series(1, $1) i
		  UNION ALL SELECT 't1', 'w', 'group', 'z' || i FROM generate_series(1, $1) i
		  UNION ALL SELECT 't1', 'v' || i, 'group', 'w' FROM generate_series(1, $1) i
		  UNION ALL SELECT 't1', 'q', 'group', 'v' || i FROM generate_series(1, $1) i`, []any{n}},
		{`ANALYZE rbac_members, rbac_groups, rbac_memberships`, nil},
	} {
		if _, err := h.pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("q"), MaxDuration: 8 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	u := rbac.Subject{Principal: identity("u")}
	g, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Hour, Justification: "incident"})
	if err != nil {
		t.Fatal(err)
	}
	// The rows the recursive walks of a statement make, in a transaction it rolls back.
	type node struct {
		Type  string  `json:"Node Type"`
		Rows  float64 `json:"Actual Rows"`
		Loops float64 `json:"Actual Loops"`
		Plans []node
	}
	var walked func(node) float64
	walked = func(p node) float64 {
		var sum float64
		if p.Type == "Recursive Union" {
			sum = p.Rows * p.Loops
		}
		for _, c := range p.Plans {
			sum += walked(c)
		}
		return sum
	}
	const places = 6 * n
	walks := func(what, sql string, args ...any) {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		var plan []struct{ Plan node }
		if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, FORMAT JSON) "+sql, args...).Scan(&plan); err != nil {
			t.Fatal(err)
		}
		if rows := walked(plan[0].Plan); rows > 2*places {
			t.Errorf("%s through %d places made %.0f rows walking up", what, places, rows)
		}
	}
	walks("Activate", rbac.HoldSQL, "t1", "user:u", h.now, g.ExpiresAt)
	walks("A change's authority", rbac.EndsSQL, "t1", "user:u", h.now)
	// u's places in the x_i end sooner, the latest in 40 minutes, which the activation is cut to.
	var sooner []rbac.Member
	for i := 1; i <= n; i++ {
		sooner = append(sooner, rbac.Member{Group: fmt.Sprint("x", i), Principal: u.Principal, ExpiresAt: h.now.Add(time.Duration(i) * time.Minute)})
	}
	h.events = nil
	if err := h.authz.ImportMembers(ctx, host, "t1", sooner); err != nil {
		t.Fatal(err)
	}
	if e := lastEvent(t, h); len(e.Shortened) != 1 || e.Shortened[0].ID != g.ID || !e.Shortened[0].ExpiresAt.Equal(h.now.Add(n*time.Minute)) {
		t.Fatalf("the activation isn't reported cut short to when u's latest path ends: %+v", e)
	}
	walks("Ending places sooner", rbac.RestsSQL, "t1", []string{g.ID}, h.now)
}

// An identity whose membership is made to end sooner, and ends, joins again in none of its groups
// and with none of the activations it made through them.
func TestJoiningAgainGivesBackNoActivationThroughAGroup(t *testing.T) {
	h, u, _ := activatedThroughOncall(t, false)
	ctx := t.Context()
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: u.Principal, ExpiresAt: h.now.Add(time.Minute)}}); err != nil {
		t.Fatal(err)
	}
	h.now = h.now.Add(time.Hour)
	if _, err := h.authz.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	if of, err := h.authz.GroupsOf(ctx, "t1", u.Principal); err != nil || len(of) != 0 {
		t.Fatalf("GroupsOf = %v, %v", of, err)
	}
	if allowed(t, h, u, root, cluster) {
		t.Error("joined again in no group, u holds sudo it activated through oncall")
	}
}

// An activation through a place a change ends holds the place until it commits, so the change
// waits for it and then ends it, rather than read the activations before it commits.
func TestEndingAPlaceWaitsForAnActivationThroughIt(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.groups(t, "oncall")
	u := h.as(t, "u", "inner")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "oncall", Principal: groupOf("inner")}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("oncall"), MaxDuration: 8 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := h.authz.WithTx(tx).Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 8 * time.Hour, Justification: "incident"}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "oncall", Principal: groupOf("inner")}})
	}()
	commitOnceWaitedOn(t, h, tx, done)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, u, root, cluster) {
		t.Error("u holds sudo it activated through a place removed while it activated")
	}
}

// Two changes that share no lock, each ending or shortening one of the two paths an activation
// rests on, end it or cut it short as they would one after the other: the second waits for the
// first, which holds the activation, and reads the path it left, rather than each read the other's
// as it was, and neither cut it.
func TestChangesEndingEachOfAnActivationsPathsAtOnceEndIt(t *testing.T) {
	type change func(ctx context.Context, h *harness, a *rbac.Authorizer) error
	// u's place in m, or m's or n's in g1, which u activated through.
	leaveM := func(ctx context.Context, _ *harness, a *rbac.Authorizer) error {
		return a.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "m", Principal: identity("u")}})
	}
	takeOutOfM := func(ctx context.Context, _ *harness, a *rbac.Authorizer) error {
		return a.ChangeMembers(ctx, rbac.Subject{Principal: identity("manager")}, "t1", nil, []rbac.Member{{Group: "m", Principal: identity("u")}})
	}
	takeOverM := func(ctx context.Context, _ *harness, a *rbac.Authorizer) error {
		return a.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "m", Source: "directory"}})
	}
	shortenM := func(ctx context.Context, h *harness, a *rbac.Authorizer) error {
		return a.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "m", Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}})
	}
	leaveN := func(ctx context.Context, _ *harness, a *rbac.Authorizer) error {
		return a.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "g1", Principal: groupOf("n")}})
	}
	deleteN := func(ctx context.Context, _ *harness, a *rbac.Authorizer) error {
		return a.DeletePrincipal(ctx, host, "t1", groupOf("n"))
	}
	deleteGroupN := func(ctx context.Context, _ *harness, a *rbac.Authorizer) error {
		return a.DeleteGroups(ctx, host, "t1", []string{"n"})
	}
	for name, c := range map[string]struct {
		m, n change
		// shortened is whether the change to m leaves u in g1 for an hour more.
		shortened bool
	}{
		"DeleteMembers and DeleteMembers":                    {m: leaveM, n: leaveN},
		"ChangeMembers and DeleteMembers":                    {m: takeOutOfM, n: leaveN},
		"ChangeMembers and DeletePrincipal":                  {m: takeOutOfM, n: deleteN},
		"ChangeMembers and DeleteGroups":                     {m: takeOutOfM, n: deleteGroupN},
		"ImportGroups taking a group over and DeleteMembers": {m: takeOverM, n: leaveN},
		"ImportMembers shortening a place and DeleteGroups":  {m: shortenM, n: deleteGroupN, shortened: true},
	} {
		for _, order := range []string{"serially", "at once", "at once the other way"} {
			t.Run(name+" "+order, func(t *testing.T) {
				h := grouped(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
				ctx := t.Context()
				h.groups(t, "g1", "m", "n")
				h.as(t, "manager")
				u := h.as(t, "u", "m", "n")
				if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "g1", Principal: groupOf("m")}, {Group: "g1", Principal: groupOf("n")}}); err != nil {
					t.Fatal(err)
				}
				if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("g1"), MaxDuration: 8 * time.Hour}); err != nil {
					t.Fatal(err)
				}
				if _, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 8 * time.Hour, Justification: "incident"}); err != nil {
					t.Fatal(err)
				}
				first, second := c.m, c.n
				if order == "at once the other way" {
					first, second = c.n, c.m
				}
				if order == "serially" {
					if err := first(ctx, h, h.authz); err != nil {
						t.Fatal(err)
					}
					if err := second(ctx, h, h.authz); err != nil {
						t.Fatal(err)
					}
				} else {
					tx, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = tx.Rollback(ctx) }()
					if err := first(ctx, h, h.authz.WithTx(tx)); err != nil {
						t.Fatal(err)
					}
					done := make(chan error, 1)
					go func() { done <- second(ctx, h, h.authz) }()
					commitOnceWaitedOn(t, h, tx, done)
					if err := <-done; err != nil {
						t.Fatal(err)
					}
				}
				if c.shortened {
					h.now = h.now.Add(59 * time.Minute)
					if !allowed(t, h, u, root, cluster) {
						t.Fatal("u lost sudo while still in g1 through m")
					}
				}
				h.now = h.now.Add(time.Hour)
				if allowed(t, h, u, root, cluster) {
					of, err := h.authz.GroupsOf(ctx, "t1", u.Principal)
					t.Errorf("u, in groups %v (%v) and none of them in g1, holds sudo it activated through g1", of, err)
				}
			})
		}
	}
}

// Activate finds its subject eligible only through the places in groups it holds: through a place
// nested once it holds them, which no change removing it waits for, the activation would outlast
// the place, removed before it commits.
func TestAnActivationIsEligibleOnlyThroughThePlacesItHolds(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.groups(t, "oncall")
	u := h.as(t, "u", "inner")
	nesting := []rbac.Member{{Group: "oncall", Principal: groupOf("inner")}}
	if err := h.authz.ImportMembers(ctx, host, "t1", nesting); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("oncall"), MaxDuration: 8 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	// inner leaves oncall as Activate begins holding u's places, and is nested in it again once it
	// holds them.
	rbac.SetHoldingPlaces(t, func() func() {
		if err := h.authz.DeleteMembers(ctx, host, "t1", nesting); err != nil {
			t.Error(err)
		}
		return func() {
			if err := h.authz.ImportMembers(ctx, host, "t1", nesting); err != nil {
				t.Error(err)
			}
		}
	})
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = h.authz.WithTx(tx).Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 8 * time.Hour, Justification: "incident"})
	if err == nil {
		done := make(chan error, 1)
		go func() { done <- h.authz.DeleteMembers(ctx, host, "t1", nesting) }()
		commitOnceWaitedOn(t, h, tx, done)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if allowed(t, h, u, root, cluster) {
			t.Fatal("u holds sudo through a place removed while it activated")
		}
	}
	if !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("activating through a place nested once u's were held: %v", err)
	}
}

// A change ending one place and writing another holds both in order before it writes either, as
// Activate holds them: holding only the one it ends first, its write of the other would wait on an
// Activate holding that one and waiting on the first.
func TestEndingAPlaceAndChangingAnotherNeverDeadlocksWithAnActivation(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.groups(t, "a", "g1", "g2")
	v := h.as(t, "v", "g1", "g2")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "a", Principal: groupOf("g1")}, {Group: "a", Principal: groupOf("g2")}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("a"), MaxDuration: 8 * time.Hour}); err != nil {
		t.Fatal(err)
	}
	// Holding the place the change ends, so the change waits for it holding nothing, and Activate,
	// holding g1's place, waits behind the change.
	hold, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Rollback(ctx) }()
	var pid int
	if err := hold.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	if _, err := hold.Exec(ctx, `SELECT FROM rbac_members WHERE tenant = 't1' AND group_id = 'a' AND principal = 'group:g2' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	blocked := func() int {
		var n int
		if err := h.pool.QueryRow(ctx, `WITH RECURSIVE waiting(pid) AS (
			SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
			UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid = ANY(pg_blocking_pids(a.pid)))
			SELECT count(*) FROM waiting`, pid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	imported, activated := make(chan error, 1), make(chan error, 1)
	waiting := func(n int) {
		for blocked() < n {
			select {
			case err := <-imported:
				t.Fatalf("ImportMembers ran while the place was held: %v", err)
			case err := <-activated:
				t.Fatalf("Activate ran while the place was held: %v", err)
			default:
			}
		}
	}
	go func() {
		imported <- h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
			{Group: "a", Principal: groupOf("g1"), Note: "renamed"},
			{Group: "a", Principal: groupOf("g2"), ExpiresAt: h.now.Add(time.Hour)},
		})
	}()
	waiting(1)
	go func() {
		_, err := h.authz.Activate(ctx, v, cluster, rbac.Activation{Role: "cluster.sudo", Duration: 30 * time.Minute, Justification: "incident"})
		activated <- err
	}()
	waiting(2)
	if err := hold.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-imported; err != nil {
		t.Errorf("ImportMembers: %v", err)
	}
	if err := <-activated; err != nil {
		t.Errorf("Activate: %v", err)
	}
}

// Revoking activations locks them in the order a change ending their places locks them, which
// holds no lock of their scope: deleted in the order of their ids or where they are stored, a
// revoke would hold one the change locks last and wait on one it locks first.
func TestRevokingActivationsAndEndingThemAtOnceNeverDeadlocks(t *testing.T) {
	for name, revoke := range map[string]func(ctx context.Context, h *harness, revokes []rbac.Binding) error{
		"Apply": func(ctx context.Context, h *harness, revokes []rbac.Binding) error {
			return h.authz.Apply(ctx, rbac.Subject{Principal: identity("owner")}, cluster, rbac.Change{Revoke: revokes})
		},
		"DeleteGrants": func(ctx context.Context, h *harness, revokes []rbac.Binding) error {
			grants := make([]rbac.Grant, len(revokes))
			for i, b := range revokes {
				grants[i] = rbac.Grant{Scope: cluster.Scope(), Binding: b}
			}
			return h.authz.DeleteGrants(ctx, host, "t1", grants)
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := grouped(t)
			ctx := t.Context()
			h.groups(t, "g1", "x")
			if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "g1", Principal: groupOf("x")}}); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("g1"), MaxDuration: 8 * time.Hour}); err != nil {
				t.Fatal(err)
			}
			// w's activation first by id and where it is stored, and u's, which the change locks
			// first, last.
			var revokes []rbac.Binding
			for i, id := range []string{"w", "v", "u"} {
				s := h.as(t, id, "x")
				if _, err := h.authz.Activate(ctx, s, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Hour, Justification: "incident"}); err != nil {
					t.Fatal(err)
				}
				if _, err := h.pool.Exec(ctx, `UPDATE rbac_grants SET id = $1 WHERE principal = $2 AND source = 'activation'`,
					fmt.Sprintf("00000000-0000-4000-8000-%012d", i+1), "user:"+id); err != nil {
					t.Fatal(err)
				}
				revokes = append(revokes, rbac.Binding{Role: "cluster.sudo", Principal: s.Principal, Source: rbac.SourceActivation})
			}
			for _, order := range []string{"id", "ctid"} {
				var first string
				if err := h.pool.QueryRow(ctx, `SELECT principal FROM rbac_grants WHERE source = 'activation' ORDER BY `+order+` LIMIT 1`).Scan(&first); err != nil || first != "user:w" {
					t.Fatalf("first activation by %s: %s, %v", order, first, err)
				}
			}
			// Holding v's, so the change locks u's and waits, and the revoke waits behind it.
			hold, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = hold.Rollback(ctx) }()
			var pid int
			if err := hold.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
				t.Fatal(err)
			}
			if _, err := hold.Exec(ctx, `SELECT FROM rbac_grants WHERE principal = 'user:v' AND source = 'activation' FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			ended, revoked := make(chan error, 1), make(chan error, 1)
			waiting := func(n int) {
				t.Helper()
				for {
					var blocked int
					if err := h.pool.QueryRow(ctx, `WITH RECURSIVE waiting(pid) AS (
						SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))
						UNION SELECT a.pid FROM pg_stat_activity a JOIN waiting w ON w.pid = ANY(pg_blocking_pids(a.pid)))
						SELECT count(*) FROM waiting`, pid).Scan(&blocked); err != nil {
						t.Fatal(err)
					}
					if blocked >= n {
						return
					}
					select {
					case err := <-ended:
						t.Fatalf("DeleteMembers ran while v's activation was held: %v", err)
					case err := <-revoked:
						t.Fatalf("%s ran while v's activation was held: %v", name, err)
					default:
					}
				}
			}
			go func() {
				ended <- h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "g1", Principal: groupOf("x")}})
			}()
			waiting(1)
			go func() { revoked <- revoke(ctx, h, revokes) }()
			waiting(2)
			if err := hold.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-ended; err != nil {
				t.Errorf("DeleteMembers: %v", err)
			}
			if err := <-revoked; err != nil {
				t.Errorf("%s: %v", name, err)
			}
			if grants, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}}); err != nil || slices.ContainsFunc(grants, func(g rbac.Grant) bool {
				return g.Source == rbac.SourceActivation
			}) {
				t.Errorf("activations left: %+v, %v", grants, err)
			}
		})
	}
}

func TestAnActivationIsHandedOnNoLongerThanItLasts(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), granter) })
	ctx := t.Context()
	// u changes grants on the cluster for good, and holds sudo for an hour, as boss approved.
	h.seed(t, grant(cluster.Scope(), "cluster.granter", rbac.User, "u"))
	u, boss, v := h.as(t, "u"), h.as(t, "boss"), h.as(t, "v")
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{
		Role: "cluster.sudo", Principal: u.Principal,
		MaxDuration: time.Hour, Approvers: []rbac.Principal{boss.Principal},
	}); err != nil {
		t.Fatal(err)
	}
	activated, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Hour, Justification: "INC-1", Approver: boss})
	if err != nil {
		t.Fatal(err)
	}
	sudo := func(p rbac.Principal, until time.Time) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: p, ExpiresAt: until}}}
	}
	for name, until := range map[string]time.Time{"for good": {}, "past its end": activated.ExpiresAt.Add(time.Microsecond)} {
		for _, to := range []rbac.Subject{u, v} {
			if err := h.authz.Apply(ctx, u, cluster, sudo(to.Principal, until)); !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("an activation handed on to %s %s: %v", to.Principal.ID, name, err)
			}
		}
	}
	// An eligibility is activated on terms its setter chooses, such as no approver, so even one
	// ending with the activation would outlast what boss approved.
	for _, until := range []time.Time{{}, activated.ExpiresAt} {
		e := rbac.Eligibility{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour, ExpiresAt: until}
		if err := h.authz.SetEligibility(ctx, u, cluster, e); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("an activation handed on as an eligibility until %v: %v", until, err)
		}
	}
	if roles, err := h.authz.Grantable(ctx, u, cluster); err != nil || slices.ContainsFunc(roles, func(r rbac.RoleDefinition) bool { return r.ID == "cluster.sudo" }) {
		t.Errorf("Grantable offers what u may grant only until its activation ends: %v, %v", roles, err)
	}
	if err := h.authz.Apply(ctx, u, cluster, sudo(v.Principal, activated.ExpiresAt)); err != nil {
		t.Fatalf("an activation handed on until it ends: %v", err)
	}
	h.now = activated.ExpiresAt
	if allowed(t, h, u, root, cluster) || allowed(t, h, v, root, cluster) {
		t.Fatal("what was handed on outlived the activation")
	}
}

func TestAnActivatedPowerToChangeGrantsIsHandedOnNoLongerThanItLasts(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), granter) })
	ctx := t.Context()
	// u holds sudo for good, and activates the power to change grants on the cluster for an hour.
	h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.User, "u"))
	u := h.as(t, "u")
	h.as(t, "v")
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.granter", Principal: u.Principal, MaxDuration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	activated, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.granter", Duration: time.Hour, Justification: "INC-1"})
	if err != nil {
		t.Fatal(err)
	}
	to := func(role rbac.Role, until time.Time) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: role, Principal: identity("v"), ExpiresAt: until}}}
	}
	if err := h.authz.Apply(ctx, u, cluster, to("cluster.admin", time.Time{})); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("the power activated for an hour handed on for good: %v", err)
	}
	if err := h.authz.Apply(ctx, u, cluster, to("cluster.admin", activated.ExpiresAt)); err != nil {
		t.Errorf("handed on until it ends: %v", err)
	}
	// What u holds for good, it grants for good through it.
	if err := h.authz.Apply(ctx, u, cluster, to("cluster.sudo", time.Time{})); err != nil {
		t.Errorf("what its holder holds for good granted for good through it: %v", err)
	}
}

func TestWhatEndsIsHandedOnNoLongerThanItsLatestHolding(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), granter) })
	ctx := t.Context()
	hour, later := h.now.Add(time.Hour), h.now.Add(3*time.Hour)
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}, {ID: "night"}, {ID: "inner"}, {ID: "outer"}}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "g", "m", "n", "p", "v", "x")
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("m"), ExpiresAt: hour}}); err != nil {
		t.Fatal(err)
	}
	expiring := grant(cluster.Scope(), "cluster.sudo", rbac.User, "g")
	expiring.ExpiresAt = hour
	// g holds sudo until a time; m holds it for good, but is a member until then; n is in a group
	// holding it until then; p is in a group in one holding it until then; and v is in two groups
	// holding it, its place in one ending later.
	h.seed(t, expiring, grant(cluster.Scope(), "cluster.sudo", rbac.User, "m"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "ops"),
		grant(cluster.Scope(), "cluster.sudo", rbac.Group, "night"), grant(cluster.Scope(), "cluster.sudo", rbac.Group, "outer"))
	for _, id := range []string{"g", "m", "n", "p", "v"} {
		h.seed(t, grant(cluster.Scope(), "cluster.granter", rbac.User, id))
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "ops", Principal: identity("n"), ExpiresAt: hour},
		{Group: "inner", Principal: identity("p")},
		{Group: "outer", Principal: groupOf("inner"), ExpiresAt: hour},
		{Group: "ops", Principal: identity("v"), ExpiresAt: hour},
		{Group: "night", Principal: identity("v"), ExpiresAt: later},
	}); err != nil {
		t.Fatal(err)
	}
	sudo := func(until time.Time) rbac.Change {
		return rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: identity("x"), ExpiresAt: until}}}
	}
	for id, ends := range map[string]time.Time{"g": hour, "m": hour, "n": hour, "p": hour, "v": later} {
		actor := rbac.Subject{Principal: identity(id)}
		for name, until := range map[string]time.Time{"for good": {}, "past its end": ends.Add(time.Second)} {
			if err := h.authz.Apply(ctx, actor, cluster, sudo(until)); !errors.Is(err, rbac.ErrDenied) {
				t.Errorf("%s handing sudo on %s: %v", id, name, err)
			}
		}
		if err := h.authz.Apply(ctx, actor, cluster, sudo(ends)); err != nil {
			t.Errorf("%s handing sudo on until its holding ends: %v", id, err)
		}
	}
}

// Grants of one role in one change are each decided by what the actor holds under their condition
// until they end, however many share a decision.
func TestGrantsInOneChangeAreEachDecidedByWhatTheActorHoldsThen(t *testing.T) {
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), granter) })
	ctx := t.Context()
	hour, later := h.now.Add(time.Hour), h.now.Add(3*time.Hour)
	mfa := rbac.Condition{Expression: `request.attributes.mfa == true`}
	other := rbac.Condition{Expression: `request.attributes.site == "lab"`}
	// u changes grants for good, and holds sudo until an hour from now, and under mfa until later.
	sudo, underMFA := grant(cluster.Scope(), "cluster.sudo", rbac.User, "u"), grant(cluster.Scope(), "cluster.sudo", rbac.User, "u")
	sudo.ExpiresAt, underMFA.ExpiresAt, underMFA.Condition = hour, later, mfa
	h.seed(t, grant(cluster.Scope(), "cluster.granter", rbac.User, "u"), sudo, underMFA)
	u := h.as(t, "u")
	cases := []struct {
		until   time.Time
		under   rbac.Condition
		granted bool
	}{
		{hour.Add(-time.Second), rbac.Condition{}, true},
		{hour, rbac.Condition{}, true},
		{hour, other, true},
		{hour.Add(time.Second), rbac.Condition{}, false},
		{hour.Add(time.Second), other, false},
		{hour.Add(time.Second), mfa, true},
		{later, mfa, true},
		{later.Add(time.Second), mfa, false},
		{time.Time{}, mfa, false},
		{time.Time{}, rbac.Condition{}, false},
	}
	var all, granted rbac.Change
	refused := 0
	for i, c := range cases {
		b := rbac.Binding{Role: "cluster.sudo", Principal: identity(fmt.Sprintf("p%d", i)), ExpiresAt: c.until, Condition: c.under}
		all.Grant = append(all.Grant, b)
		if c.granted {
			granted.Grant = append(granted.Grant, b)
		} else {
			refused++
		}
	}
	err := h.authz.Apply(ctx, u, cluster, all)
	joined, ok := err.(interface{ Unwrap() []error })
	if !ok || len(joined.Unwrap()) != refused || !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("want %d of the grants refused, got %v", refused, err)
	}
	if err := h.authz.Apply(ctx, u, cluster, granted); err != nil {
		t.Fatalf("the grants u holds sudo for, under their condition until they end: %v", err)
	}
}

func TestDefiningARoleNeedsWhatItGivesHeldForGood(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	tenant := rbac.TenantRoot("t1")
	expiring := grant(tenant, "cluster.sudo", rbac.User, "definer")
	expiring.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, grant(tenant, "tenant.roles", rbac.User, "definer"), expiring)
	definer := h.as(t, "definer")
	r := rbac.RoleDefinition{ID: "custom.root", Permissions: []rbac.Permission{root}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, definer, "t1", r); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("defining a role from what the definer holds for an hour: %v", err)
	}
	h.seed(t, grant(tenant, "cluster.sudo", rbac.User, "definer"))
	if err := h.authz.SetRole(ctx, definer, "t1", r); err != nil {
		t.Fatalf("from what it holds for good: %v", err)
	}
}

func TestChangingMembersHandsOnNoLongerThanTheActorHolds(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), granter) })
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}, {ID: "oncall"}}); err != nil {
		t.Fatal(err)
	}
	// lead changes ops' and oncall's members, and grants on the cluster, for good, but holds sudo,
	// which ops holds and oncall may activate, only for an hour.
	hour := h.now.Add(time.Hour)
	expiring := grant(cluster.Scope(), "cluster.sudo", rbac.User, "lead")
	expiring.ExpiresAt = hour
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead"), grant(cluster.Scope(), "cluster.granter", rbac.User, "lead"), expiring,
		grant(cluster.Scope(), "cluster.sudo", rbac.Group, "ops"))
	if err := h.authz.SetEligibility(ctx, h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf("oncall"), MaxDuration: time.Minute}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	lead := h.as(t, "lead")
	in := func(group string, until time.Time) []rbac.Member {
		return []rbac.Member{{Group: group, Principal: identity("u"), ExpiresAt: until}}
	}
	for name, add := range map[string][]rbac.Member{
		"for good":                     in("ops", time.Time{}),
		"past the holding's end":       in("ops", hour.Add(time.Second)),
		"eligible, ending before then": in("oncall", hour.Add(-time.Minute)),
	} {
		if err := h.authz.ChangeMembers(ctx, lead, "t1", add, nil); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("a place in a group handing sudo on %s: %v", name, err)
		}
	}
	if err := h.authz.ChangeMembers(ctx, lead, "t1", in("ops", hour), nil); err != nil {
		t.Fatalf("a place ending with the holding: %v", err)
	}
}

// meanwhileAsked is a harness whose host runs meanwhile, once, the first time it is asked about a
// grant made as via, as another change committing between a change's checks and its transaction.
func meanwhileAsked(t *testing.T, via rbac.Via, meanwhile *func(context.Context) error) *harness {
	t.Helper()
	return grouped(t, func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			if do := *meanwhile; do != nil && in.Via == via {
				*meanwhile = nil
				if err := do(ctx); err != nil {
					return err
				}
			}
			return validate(ctx, q, in)
		}
	})
}

// Scopes a change to members reaches decide together where the actor holds the same grants on
// each, and one whose grants changed meanwhile decides apart under the locks: with no constraints
// to ask, nothing it checks there was missed before the transaction, so the change goes through.
func TestAScopeDecidedApartUnderTheLocksIsNoConflict(t *testing.T) {
	var meanwhile func(context.Context) error
	h := meanwhileAsked(t, rbac.ViaMembership, &meanwhile)
	ctx := t.Context()
	a, b := rbac.Scope{Type: "cluster", ID: "a"}, rbac.Scope{Type: "cluster", ID: "b"}
	h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.admin", rbac.User, "lead"), grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "lead"),
		grant(a, "cluster.login", rbac.Group, "crew"), grant(b, "cluster.login", rbac.Group, "crew"))
	h.join(t, "u")
	meanwhile = func(ctx context.Context) error {
		return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(b, "cluster.login", rbac.User, "lead")})
	}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "lead"), "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}}, nil); err != nil {
		t.Fatalf("a member gaining what crew holds, once the actor's grants on one scope changed meanwhile: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("lead should have been granted on b meanwhile")
	}
}

func TestAGrantToAGroupAMemberJoinedWhileTheHostWasAskedIsTriedAgain(t *testing.T) {
	var meanwhile func(context.Context) error
	h := meanwhileAsked(t, rbac.ViaApply, &meanwhile)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}}); err != nil {
		t.Fatal(err)
	}
	h.join(t, "g1")
	meanwhile = func(ctx context.Context) error {
		return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity("g1")}})
	}
	sudo := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: groupOf("ops")}}}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, sudo); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a grant to a group that gained a member while the host was asked: %v", err)
	}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, sudo); err != nil {
		t.Fatalf("tried again: %v", err)
	}
}

func TestAGrantToAnIdentityThatLeftWhileTheHostWasAskedIsTriedAgain(t *testing.T) {
	var meanwhile func(context.Context) error
	h := meanwhileAsked(t, rbac.ViaApply, &meanwhile)
	ctx := t.Context()
	h.join(t, "u")
	meanwhile = func(ctx context.Context) error { return h.authz.DeletePrincipal(ctx, host, "t1", identity("u")) }
	sudo := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: identity("u")}}}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, sudo); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a grant to an identity that left while the host was asked: %v", err)
	}
	if got, err := h.authz.Grants(ctx, "t1", rbac.GrantFilter{Principals: []rbac.Principal{identity("u")}}); err != nil || len(got) != 0 {
		t.Fatalf("Grants = %+v, %v", got, err)
	}
}

func TestDeleteExpiredRunsAtReadCommitted(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	tx, err := h.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := h.authz.WithTx(tx).DeleteExpired(ctx); err == nil {
		t.Fatal("DeleteExpired at REPEATABLE READ")
	}
}

func TestTheHostTakingAGroupOverRemovesTheMembersATenantPutInIt(t *testing.T) {
	h := grouped(t, func(c *rbac.Config) { c.Sources = []string{"directory"} })
	ctx := t.Context()
	if err := h.authz.SetGroup(ctx, h.as(t, "groups"), "t1", rbac.GroupDefinition{ID: "dir-admins"}); err != nil {
		t.Fatal(err)
	}
	manager := h.as(t, "manager")
	// It holds nothing yet, so a tenant's manager may add itself.
	if err := h.authz.ChangeMembers(ctx, manager, "t1", []rbac.Member{{Group: "dir-admins", Principal: manager.Principal}}, nil); err != nil {
		t.Fatal(err)
	}
	h.events = nil
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "dir-admins", Source: "directory"}}); err != nil {
		t.Fatal(err)
	}
	if len(h.events) != 1 || len(h.events[0].Left) != 1 {
		t.Fatalf("events = %+v", h.events)
	}
	if got, err := h.authz.Members(ctx, "t1", "dir-admins"); err != nil || len(got) != 0 {
		t.Fatalf("Members = %+v, %v", got, err)
	}
}

func TestChangingMembersOfALabeledGroupNeedsItsLabel(t *testing.T) {
	crew := rbac.Resource{Tenant: "t1", Type: rbac.GroupScope, ID: "crew", Labels: rbac.Label{"level": {"high"}}}
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == crew.Scope() {
				return crew, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.groups(t, "crew")
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"))
	h.join(t, "u")
	admin := h.as(t, "admin")
	add := []rbac.Member{{Group: "crew", Principal: identity("u")}}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", add, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("changing a labeled group's members without its label: %v", err)
	}
	h.hold(t, "admin", "level:high")
	if err := h.authz.ChangeMembers(ctx, admin, "t1", add, nil); err != nil {
		t.Fatalf("with its label: %v", err)
	}
}

func TestManagingALabeledGroupNeedsItsLabel(t *testing.T) {
	high := rbac.Label{"level": {"high"}}
	var meanwhile func(context.Context) error
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers,
			rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}})
		resourceOf := c.ResourceOf
		// The groups whose ids start with "vault", made or not, the host labels.
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s.Type == rbac.GroupScope && strings.HasPrefix(s.ID, "vault") {
				return rbac.Resource{Tenant: tenant, Type: s.Type, ID: s.ID, Labels: high}, nil
			}
			return resourceOf(ctx, tenant, s)
		}
		// Asked about the actor's clearance, before the change's transaction, the host revokes it.
		c.Constraints = []rbac.Constraint{{Name: "meanwhile", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if do := meanwhile; do != nil && in.Permission == "level:high" {
				meanwhile = nil
				return false, do(ctx)
			}
			return false, nil
		}}}
	})
	ctx := t.Context()
	h.groups(t, "vault", "plain")
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "vault", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"))
	admin := h.as(t, "admin")
	// As changing its members needs its label, so do renaming it, deleting it with them, and making it.
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "vault", Principal: identity("u")}}); !errors.Is(err, rbac.ErrDenied) {
		t.Fatalf("removing a labeled group's member without its label: %v", err)
	}
	if err := h.authz.SetGroup(ctx, admin, "t1", rbac.GroupDefinition{ID: "vault", Name: "renamed"}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("renaming a labeled group without its label: %v", err)
	}
	if err := h.authz.DeleteGroup(ctx, admin, "t1", "vault"); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("deleting a labeled group without its label: %v", err)
	}
	if err := h.authz.SetGroup(ctx, admin, "t1", rbac.GroupDefinition{ID: "vault-new"}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("making a group the host labels without its label: %v", err)
	}
	if err := h.authz.SetGroup(ctx, admin, "t1", rbac.GroupDefinition{ID: "plain", Name: "renamed"}); err != nil {
		t.Errorf("renaming an unlabeled group: %v", err)
	}
	if err := h.authz.DeleteGroup(ctx, admin, "t1", "plain"); err != nil {
		t.Errorf("deleting an unlabeled group: %v", err)
	}
	if of, err := h.authz.GroupsOf(ctx, "t1", identity("u")); err != nil || !slices.Equal(of, []string{"vault"}) {
		t.Fatalf("GroupsOf = %v, %v", of, err)
	}
	// With it, each is checked again under the change's locks.
	h.hold(t, "admin", "level:high")
	for name, change := range map[string]func() error{
		"SetGroup": func() error {
			return h.authz.SetGroup(ctx, admin, "t1", rbac.GroupDefinition{ID: "vault", Name: "renamed"})
		},
		"DeleteGroup": func() error { return h.authz.DeleteGroup(ctx, admin, "t1", "vault") },
	} {
		meanwhile = func(ctx context.Context) error {
			return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(rbac.TenantRoot("t1"), "level.high", rbac.User, "admin")})
		}
		if err := change(); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s once the actor lost the group's label meanwhile: %v", name, err)
		}
		if meanwhile != nil {
			t.Fatalf("%s: the clearance should have been revoked meanwhile", name)
		}
		h.hold(t, "admin", "level:high")
	}
	if err := h.authz.SetGroup(ctx, admin, "t1", rbac.GroupDefinition{ID: "vault", Name: "renamed"}); err != nil {
		t.Errorf("renaming a labeled group with its label: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "vault", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	if err := h.authz.DeleteGroup(ctx, admin, "t1", "vault"); err != nil {
		t.Errorf("deleting a labeled group with its label: %v", err)
	}
}

// A change reads the actor's label values once before its transaction and once in it, however many
// labels it checks: managing a labeled group in a labeled tenant reads them no more than managing
// an unlabeled one.
func TestManagingALabeledGroupReadsTheActorsLabelValuesOnce(t *testing.T) {
	high := rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog),
			rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}})
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == rbac.TenantRoot("t1") || s == (rbac.Scope{Type: rbac.GroupScope, ID: "vault"}) {
				return rbac.Resource{Tenant: tenant, Type: s.Type, ID: s.ID, Labels: high}, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "admin"))
	admin := h.as(t, "admin")
	h.hold(t, "admin", "level:high")
	reads := 0
	rbac.SetReadingRoles(t, func() { reads++ })
	count := func(id string) int {
		t.Helper()
		reads = 0
		if err := h.authz.SetGroup(ctx, admin, "t1", rbac.GroupDefinition{ID: id}); err != nil {
			t.Fatal(err)
		}
		return reads
	}
	if plain, vault := count("plain"), count("vault"); vault != plain {
		t.Errorf("making an unlabeled group read the actor's grants %d times, and a labeled one %d", plain, vault)
	}
}

// Deleting a group that doesn't exist does nothing, and has no label to ask the host for; one made
// while the deletion waits for its locks, whose label it didn't read, is tried again.
func TestDeletingAMissingGroupAsksTheHostNothing(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog),
			rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}})
		resourceOf := c.ResourceOf
		// The host knows only the groups it made.
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s.Type == rbac.GroupScope {
				return rbac.Resource{}, fmt.Errorf("the host has no group %q", s.ID)
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "admin"))
	admin := h.as(t, "admin")
	if err := h.authz.DeleteGroup(ctx, admin, "t1", "missing"); err != nil {
		t.Fatalf("deleting a group that doesn't exist: %v", err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "missing"}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.authz.DeleteGroup(ctx, admin, "t1", "missing") }()
	commitOnceWaitedOn(t, h, tx, done)
	if err := <-done; !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("deleting a group made while the deletion waited: %v", err)
	}
	if got, err := h.authz.Groups(ctx, "t1"); err != nil || len(got) != 1 {
		t.Fatalf("Groups = %+v, %v", got, err)
	}
}

// Without declared labels no group's label is read, so a group made while a deletion waits for its
// locks has nothing unchecked to try again for: it is deleted.
func TestDeletingAGroupMadeMeanwhileWithoutLabelsDeletesIt(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	manager := h.as(t, "groups")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "fresh"}}); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- h.authz.DeleteGroup(ctx, manager, "t1", "fresh") }()
	commitOnceWaitedOn(t, h, tx, done)
	if err := <-done; err != nil {
		t.Fatalf("deleting a group made while the deletion waited: %v", err)
	}
	if got, err := h.authz.Groups(ctx, "t1"); err != nil || slices.ContainsFunc(got, func(g rbac.GroupDefinition) bool { return g.ID == "fresh" }) {
		t.Fatalf("Groups = %+v, %v", got, err)
	}
}

func TestRemovingAMemberNeedsTheLabelOfWhereItsGroupsHoldAccess(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	// Groups holding a grant, an eligibility and an approval on the labeled cluster, one a deny there
	// exempts, one in the first, and one holding access only elsewhere.
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"),
		grant(secret.Scope(), "cluster.login", rbac.Group, "crew"), grant(workspace.Scope(), "workspace.admin", rbac.Group, "plain"))
	h.groups(t, "eligible", "approvers", "exempt", "inner")
	for _, q := range []string{
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
		 VALUES ('t1', 'cluster', 'c1', 'group', 'eligible', 'cluster.login', 3600, '{}'),
		   ('t1', 'cluster', 'c1', 'user', 'x', 'cluster.login', 3600, '{group:approvers}')`,
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		 VALUES ('t1', 'cluster', 'c1', 'd', '{members:t1}', '{group:exempt}', '{cluster:root}')`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	h.join(t, "u")
	labeledGroups := []string{"crew", "eligible", "approvers", "exempt", "inner"}
	var members []rbac.Member
	for _, g := range append(labeledGroups, "plain") {
		members = append(members, rbac.Member{Group: g, Principal: identity("u")})
	}
	if err := h.authz.ImportMembers(ctx, host, "t1", append(members, rbac.Member{Group: "crew", Principal: groupOf("inner")})); err != nil {
		t.Fatal(err)
	}
	admin := h.as(t, "admin")
	remove := func(group string) error {
		return h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: group, Principal: identity("u")}})
	}
	for _, g := range labeledGroups {
		if err := remove(g); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("removing a member of %s without the cluster's label: %v", g, err)
		}
	}
	sooner := []rbac.Member{{Group: "crew", Principal: identity("u"), ExpiresAt: h.now.Add(time.Minute)}}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", sooner, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("ending a place in crew sooner without the cluster's label: %v", err)
	}
	if err := remove("plain"); err != nil {
		t.Errorf("removing a member of a group holding access only on unlabeled scopes: %v", err)
	}
	h.hold(t, "admin", "level:high")
	for _, g := range labeledGroups {
		if err := remove(g); err != nil {
			t.Errorf("removing a member of %s with the cluster's label: %v", g, err)
		}
	}
}

// Joining a group a deny on a labeled scope names, or one in it, binds the member there, as leaving
// one it exempts does: either takes access away, which the scope's label refuses the actor, as for
// a revoke there. So do nesting a group in one, and making a place in one last longer.
func TestJoiningAGroupADenyNamesNeedsTheLabelOfItsScope(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"), grant(secret.Scope(), "cluster.login", rbac.User, "u"))
	h.hold(t, "u", "level:high")
	h.groups(t, "named", "inner", "team", "fresh", "plain")
	// A deny on the labeled cluster names named, which inner is in; one on the unlabeled workspace
	// names plain.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		VALUES ('t1', 'cluster', 'c1', 'd', '{group:named}', '{}', '{cluster:login}'),
		  ('t1', 'workspace', 'w1', 'd', '{group:plain}', '{}', '{cluster:root}')`); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u", "w")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "named", Principal: groupOf("inner")},
		{Group: "team", Principal: identity("u")},
		{Group: "named", Principal: identity("w"), ExpiresAt: h.now.Add(time.Minute)},
	}); err != nil {
		t.Fatal(err)
	}
	admin := h.as(t, "admin")
	u := rbac.Subject{Principal: identity("u")}
	for what, add := range map[string][]rbac.Member{
		"joining a group a deny names":        {{Group: "named", Principal: u.Principal}},
		"joining a group in one":              {{Group: "inner", Principal: u.Principal}},
		"nesting a group in one":              {{Group: "named", Principal: groupOf("team")}},
		"nesting a group and joining it":      {{Group: "inner", Principal: groupOf("fresh")}, {Group: "fresh", Principal: u.Principal}},
		"making a place in one last longer":   {{Group: "named", Principal: identity("w"), ExpiresAt: h.now.Add(time.Hour)}},
		"making a place in one last for good": {{Group: "named", Principal: identity("w")}},
	} {
		if err := h.authz.ChangeMembers(ctx, admin, "t1", add, nil); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("%s without the cluster's label: %v", what, err)
		}
	}
	if !allowed(t, h, u, login, secret) {
		t.Fatal("u should still log in to the labeled cluster")
	}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", []rbac.Member{{Group: "plain", Principal: u.Principal}}, nil); err != nil {
		t.Errorf("joining a group a deny on an unlabeled scope names: %v", err)
	}
	h.hold(t, "admin", "level:high")
	if err := h.authz.ChangeMembers(ctx, admin, "t1", []rbac.Member{{Group: "named", Principal: u.Principal}}, nil); err != nil {
		t.Fatalf("joining a group a deny names with the cluster's label: %v", err)
	}
	if allowed(t, h, u, login, secret) {
		t.Error("the deny should bind u once it joined the group it names")
	}
}

// A join is tried again when, while the scopes it reaches are read from the host, a deny on a
// labeled scope comes to name the group, whose label it didn't check.
func TestADenyNamingAGroupSetWhileAJoinIsCheckedIsTriedAgain(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	var meanwhile func(ctx context.Context) error
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if do := meanwhile; do != nil && s == workspace.Scope() {
				meanwhile = nil
				if err := do(ctx); err != nil {
					return rbac.Resource{}, err
				}
			}
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"))
	h.groups(t, "crew")
	// A deny on the unlabeled workspace names crew, so the join asks the host about it.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		VALUES ('t1', 'workspace', 'w1', 'd', '{group:crew}', '{}', '{cluster:root}')`); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	meanwhile = func(ctx context.Context) error {
		_, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
			VALUES ('t1', 'cluster', 'c1', 'd', '{group:crew}', '{}', '{cluster:login}')`)
		return err
	}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "admin"), "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}}, nil); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a join to a group a deny on a labeled scope came to name meanwhile: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("a deny on the cluster should have named crew meanwhile")
	}
}

// An activation rests on its holder's place in the group of the eligibility it was made through,
// or in one in it, and outlasts the eligibility's deletion: a change to members ending it on a
// labeled scope, by removing the holder, ending its place sooner, or taking a group it is in out of
// another, is checked by the scope's label, as a revoke of it there is. Another member leaving the
// group takes nothing away there, and isn't.
func TestLeavingAGroupNeedsTheLabelOfWhereActivationsMadeThroughItAre(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	for what, c := range map[string]struct {
		// places are u's, and through is the group whose eligibility on the cluster u activates by.
		places  []rbac.Member
		through string
		leaving rbac.Member
		sooner  bool
	}{
		"removing its holder": {
			places: []rbac.Member{{Group: "crew", Principal: identity("u")}}, through: "crew",
			leaving: rbac.Member{Group: "crew", Principal: identity("u")},
		},
		"ending its holder's place sooner": {
			places: []rbac.Member{{Group: "crew", Principal: identity("u")}}, through: "crew",
			leaving: rbac.Member{Group: "crew", Principal: identity("u")}, sooner: true,
		},
		"removing a group its holder is in": {
			places: []rbac.Member{{Group: "inner", Principal: identity("u")}, {Group: "crew", Principal: groupOf("inner")}}, through: "crew",
			leaving: rbac.Member{Group: "crew", Principal: groupOf("inner")},
		},
		"removing its holder's group from one above": {
			places: []rbac.Member{{Group: "crew", Principal: identity("u")}, {Group: "outer", Principal: groupOf("crew")}}, through: "outer",
			leaving: rbac.Member{Group: "outer", Principal: groupOf("crew")},
		},
	} {
		t.Run(what, func(t *testing.T) {
			h := labeled(t, func(c *rbac.Config) {
				c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
				resourceOf := c.ResourceOf
				c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
					if s == secret.Scope() {
						return secret, nil
					}
					return resourceOf(ctx, tenant, s)
				}
			})
			ctx := t.Context()
			h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"))
			h.hold(t, "owner", "level:high")
			h.hold(t, "u", "level:high")
			h.groups(t, "crew", "inner", "outer")
			h.join(t, "u", "v")
			if err := h.authz.ImportMembers(ctx, host, "t1", append(c.places, rbac.Member{Group: "crew", Principal: identity("v")})); err != nil {
				t.Fatal(err)
			}
			owner := h.as(t, "owner")
			if err := h.authz.SetEligibility(ctx, owner, secret, rbac.Eligibility{Role: "cluster.sudo", Principal: groupOf(c.through), MaxDuration: 8 * time.Hour}); err != nil {
				t.Fatal(err)
			}
			u := rbac.Subject{Principal: identity("u")}
			if _, err := h.authz.Activate(ctx, u, secret, rbac.Activation{Role: "cluster.sudo", Duration: 8 * time.Hour, Justification: "INC-1"}); err != nil {
				t.Fatal(err)
			}
			if err := h.authz.DeleteEligibility(ctx, owner, secret, "cluster.sudo", groupOf(c.through)); err != nil {
				t.Fatal(err)
			}
			admin := h.as(t, "admin")
			change := func() error {
				if c.sooner {
					m := c.leaving
					m.ExpiresAt = h.now.Add(time.Minute)
					return h.authz.ChangeMembers(ctx, admin, "t1", []rbac.Member{m}, nil)
				}
				return h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{c.leaving})
			}
			if err := change(); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("without the cluster's label: %v", err)
			}
			if !allowed(t, h, u, root, secret) {
				t.Fatal("u's activation should still give it root on the cluster")
			}
			if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("v")}}); err != nil {
				t.Errorf("removing a member holding no activation there: %v", err)
			}
			h.hold(t, "admin", "level:high")
			h.events = nil
			if err := change(); err != nil {
				t.Fatalf("with the cluster's label: %v", err)
			}
			if e := lastEvent(t, h); len(e.Revoked)+len(e.Shortened) != 1 {
				t.Errorf("the change ended or cut short %d activations and %d grants", len(e.Shortened), len(e.Revoked))
			}
		})
	}
}

// A removal is tried again when, while the scopes it reaches are read from the host, an activation
// on a labeled scope comes to rest on the place it ends, whose label it didn't check.
func TestAnActivationMadeWhileARemovalIsCheckedIsTriedAgain(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	var meanwhile func(ctx context.Context) error
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if do := meanwhile; do != nil && s == workspace.Scope() {
				meanwhile = nil
				if err := do(ctx); err != nil {
					return rbac.Resource{}, err
				}
			}
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"), grant(workspace.Scope(), "workspace.admin", rbac.Group, "crew"))
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	// u activates on the cluster through an eligibility of crew's, which is then deleted.
	meanwhile = func(ctx context.Context) error {
		_, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role, source, expires_at, activated_through)
			VALUES ('t1', 'cluster', 'c1', 'user', 'u', 'cluster.sudo', 'activation', $1, 'group:crew')`, h.now.Add(time.Hour))
		return err
	}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "admin"), "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u")}}); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a removal ending an activation on a labeled scope made meanwhile: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("u should have activated on the cluster meanwhile")
	}
}

// A removal a label refuses is refused before its transaction, waiting for no lock another
// change holds.
func TestARemovalALabelRefusesWaitsForNoLock(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"), grant(secret.Scope(), "cluster.login", rbac.Group, "crew"))
	h.join(t, "u", "v")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	admin := h.as(t, "admin")
	// Another change to crew's members holds its locks.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := h.authz.WithTx(tx).ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("v")}}); err != nil {
		t.Fatal(err)
	}
	var pid int32
	if err := tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u")}})
	}()
	for {
		select {
		case err := <-done:
			if !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("removing a member of a group holding access on a labeled scope without its label: %v", err)
			}
			return
		default:
		}
		var waiting bool
		if err := h.pool.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_stat_activity WHERE $1::int = ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			_ = tx.Rollback(ctx)
			t.Fatalf("a removal its label refuses waited for another change's locks, then: %v", <-done)
		}
	}
}

// A member with another place in its group, from another source, doesn't leave it when one place
// is removed or ends sooner: nothing changes for it, so neither a label nor a deny is checked.
func TestRemovingOneOfAMembersPlacesChecksNothing(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers, guardRole)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"), grant(secret.Scope(), "cluster.login", rbac.Group, "crew"))
	// A deny naming crew, whose lifting would need cluster:deny there.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
		VALUES ('t1', 'cluster', 'c1', 'd', '{group:crew}', '{cluster:root}')`); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u", "v")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "crew", Principal: identity("u")},
		{Group: "crew", Principal: identity("u"), Source: "dir"},
		{Group: "crew", Principal: identity("v")},
		{Group: "crew", Principal: identity("v"), Source: "dir"},
	}); err != nil {
		t.Fatal(err)
	}
	admin := h.as(t, "admin")
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Errorf("removing one of u's two places in crew: %v", err)
	}
	sooner := []rbac.Member{{Group: "crew", Principal: identity("v"), ExpiresAt: h.now.Add(time.Minute)}}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", sooner, nil); err != nil {
		t.Errorf("ending one of v's two places in crew sooner: %v", err)
	}
	// Its last place, it leaves by.
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u"), Source: "dir"}}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("removing u's last place in crew: %v", err)
	}
	both := []rbac.Member{{Group: "crew", Principal: identity("v")}, {Group: "crew", Principal: identity("v"), Source: "dir"}}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, both); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("removing both of v's places in crew at once: %v", err)
	}
}

// A member is in its group until its last place there ends, so removing the place that outlasts its
// others, or ending it sooner, takes it out sooner: it leaves, as by its last place.
func TestRemovingThePlaceThatOutlastsAMembersOthersIsLeaving(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"), grant(secret.Scope(), "cluster.login", rbac.Group, "crew"))
	h.join(t, "u", "v", "w")
	soon, later := h.now.Add(time.Minute), h.now.Add(time.Hour)
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "crew", Principal: identity("u")},
		{Group: "crew", Principal: identity("u"), Source: "dir", ExpiresAt: later},
		{Group: "crew", Principal: identity("v")},
		{Group: "crew", Principal: identity("v"), Source: "dir", ExpiresAt: later},
		{Group: "crew", Principal: identity("w"), ExpiresAt: later},
		{Group: "crew", Principal: identity("w"), Source: "dir", ExpiresAt: later},
	}); err != nil {
		t.Fatal(err)
	}
	admin := h.as(t, "admin")
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u")}}); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("removing u's place for good, leaving one that ends in an hour: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", []rbac.Member{{Group: "crew", Principal: identity("v"), ExpiresAt: soon}}, nil); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("ending v's place for good sooner than its other: %v", err)
	}
	// Another place lasting as long keeps it in the group as long as before.
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("w")}}); err != nil {
		t.Errorf("removing one of w's two places ending at once: %v", err)
	}
}

// A scope the host reports it no longer has, as one it deleted without DeleteScopes, has no label
// to refuse taking access away there, so a removal or deleting a role reads it as unlabeled; any
// other error of the host's still fails the change.
func TestARemovalReadsAScopeTheHostNoLongerHasAsUnlabeled(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	errDown := errors.New("the host is down")
	manager := rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}}
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers, manager)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			switch s {
			case secret.Scope():
				return secret, nil
			case rbac.Scope{Type: "cluster", ID: "gone"}, rbac.Scope{Type: rbac.GroupScope, ID: "lost"}:
				return rbac.Resource{}, fmt.Errorf("%w: %s", rbac.ErrNotFound, s.Key())
			case rbac.Scope{Type: "cluster", ID: "down"}:
				return rbac.Resource{}, errDown
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types) VALUES ('t1', 'custom.viewer', '{cluster:view}', '{cluster}'),
		('t1', 'custom.ops', '{cluster:view,cluster:login}', '{cluster}')`); err != nil {
		t.Fatal(err)
	}
	gone, down := rbac.Scope{Type: "cluster", ID: "gone"}, rbac.Scope{Type: "cluster", ID: "down"}
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "tenant.roles", rbac.User, "admin"),
		grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "admin"),
		grant(gone, "cluster.login", rbac.Group, "crew"), grant(secret.Scope(), "cluster.login", rbac.Group, "crew"),
		grant(down, "cluster.login", rbac.Group, "ops"), grant(gone, "custom.viewer", rbac.User, "u"), grant(gone, "custom.ops", rbac.User, "u"))
	h.join(t, "u", "v")
	h.groups(t, "lost")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{
		{Group: "crew", Principal: identity("u")},
		{Group: "ops", Principal: identity("u")},
		{Group: "lost", Principal: identity("u")},
	}); err != nil {
		t.Fatal(err)
	}
	admin := h.as(t, "admin")
	h.hold(t, "admin", "level:high")
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Errorf("removing a member of a group with access on a scope the host no longer has: %v", err)
	}
	if err := h.authz.DeleteRole(ctx, admin, "t1", "custom.viewer"); err != nil {
		t.Errorf("deleting a role granted on a scope the host no longer has: %v", err)
	}
	// Narrowing a role only takes access away, and widening it is a change the host must read the
	// scope for.
	ops := rbac.RoleDefinition{ID: "custom.ops", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", ops); err != nil {
		t.Errorf("narrowing a role granted on a scope the host no longer has: %v", err)
	}
	ops.Permissions = []rbac.Permission{view, login}
	if err := h.authz.SetRole(ctx, admin, "t1", ops); !errors.Is(err, rbac.ErrNotFound) {
		t.Errorf("widening it: %v", err)
	}
	// So with a group the host no longer has: its members are removed, and their places made to end
	// sooner, but none added, nor any place made to last longer.
	if err := h.authz.ChangeMembers(ctx, admin, "t1", []rbac.Member{{Group: "lost", Principal: identity("v")}}, nil); !errors.Is(err, rbac.ErrNotFound) {
		t.Errorf("adding a member to a group the host no longer has: %v", err)
	}
	sooner := []rbac.Member{{Group: "lost", Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", sooner, nil); err != nil {
		t.Errorf("making a place in a group the host no longer has end sooner: %v", err)
	}
	sooner[0].Note = "leaving"
	if err := h.authz.ChangeMembers(ctx, admin, "t1", sooner, nil); err != nil {
		t.Errorf("changing the note of a place in a group the host no longer has: %v", err)
	}
	sooner[0].ExpiresAt = h.now.Add(2 * time.Hour)
	if err := h.authz.ChangeMembers(ctx, admin, "t1", sooner, nil); !errors.Is(err, rbac.ErrNotFound) {
		t.Errorf("making a place in a group the host no longer has last longer: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "lost", Principal: identity("u")}}); err != nil {
		t.Errorf("removing a member of a group the host no longer has: %v", err)
	}
	if err := h.authz.DeleteGroup(ctx, admin, "t1", "lost"); err != nil {
		t.Errorf("deleting a group the host no longer has: %v", err)
	}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "ops", Principal: identity("u")}}); !errors.Is(err, errDown) {
		t.Errorf("removing a member of a group with access on a scope the host fails to read: %v", err)
	}
}

// A place a change makes end sooner in a group the host no longer has, which it reads as unlabeled,
// is tried again where the place was removed while the change waited: it joins the group then.
func TestAPlaceEndingSoonerInAGroupTheHostLostRemovedMeanwhileIsTriedAgain(t *testing.T) {
	var meanwhile func(context.Context) error
	h := grouped(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s != (rbac.Scope{Type: rbac.GroupScope, ID: "lost"}) {
				return resourceOf(ctx, tenant, s)
			}
			if do := meanwhile; do != nil {
				meanwhile = nil
				if err := do(ctx); err != nil {
					return rbac.Resource{}, err
				}
			}
			return rbac.Resource{}, fmt.Errorf("%w: %s", rbac.ErrNotFound, s.Key())
		}
	})
	ctx := t.Context()
	h.as(t, "u", "lost")
	meanwhile = func(ctx context.Context) error {
		return h.authz.DeleteMembers(ctx, host, "t1", []rbac.Member{{Group: "lost", Principal: identity("u")}})
	}
	sooner := []rbac.Member{{Group: "lost", Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", sooner, nil); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("ending sooner a place in a group the host no longer has, removed meanwhile: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("u's place should have been removed meanwhile")
	}
	if of, err := h.authz.GroupsOf(ctx, "t1", identity("u")); err != nil || len(of) != 0 {
		t.Fatalf("u is in %v, %v", of, err)
	}
}

// Where the actor's label values satisfy every label, none can refuse it taking access away, so a
// removal asks the host nothing about the scopes it takes it away on, and is tried again where they
// no longer do once it holds its locks.
func TestARemovalByOneClearedForEveryLabelAsksTheHostNothing(t *testing.T) {
	asked := 0
	var meanwhile func(context.Context) error
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s.Type == "cluster" {
				asked++
			}
			return resourceOf(ctx, tenant, s)
		}
		c.Constraints = []rbac.Constraint{{Name: "meanwhile", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if do := meanwhile; do != nil && in.Permission == "rel:fra" {
				meanwhile = nil
				return false, do(ctx)
			}
			return false, nil
		}}}
	})
	ctx := t.Context()
	h.groups(t, "crew")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT 't1', 'cluster', 'c' || i, 'group', 'crew', 'cluster.login' FROM generate_series(1, 20) i`); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"))
	h.join(t, "u", "v")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}, {Group: "crew", Principal: identity("v")}}); err != nil {
		t.Fatal(err)
	}
	admin := h.as(t, "admin")
	h.hold(t, "admin", "level:high", "comp:alpha", "comp:bravo", "rel:usa", "rel:gbr", "rel:fra")
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	if asked != 0 {
		t.Errorf("a removal by one cleared for every label asked Config.ResourceOf about %d clusters", asked)
	}
	meanwhile = func(ctx context.Context) error {
		return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(rbac.TenantRoot("t1"), "rel.fra", rbac.User, "admin")})
	}
	if err := h.authz.ChangeMembers(ctx, admin, "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("v")}}); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a removal once the actor lost a label value meanwhile: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("the label value should have been revoked meanwhile")
	}
}

// Deleting a role only takes access away, so where the actor's label values satisfy every label it
// asks the host nothing about the scopes the role is granted on, and is tried again where they no
// longer do once it holds the tenant's lock.
func TestDeletingARoleByOneClearedForEveryLabelAsksTheHostNothing(t *testing.T) {
	asked := 0
	var meanwhile func(context.Context) error
	h := labeled(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s.Type == "cluster" {
				asked++
			}
			return resourceOf(ctx, tenant, s)
		}
		c.Constraints = []rbac.Constraint{{Name: "meanwhile", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
			if do := meanwhile; do != nil && in.Permission == "rel:fra" {
				meanwhile = nil
				return false, do(ctx)
			}
			return false, nil
		}}}
	})
	ctx := t.Context()
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		VALUES ('t1', 'custom.viewer', '{cluster:view}', '{cluster}'), ('t1', 'custom.other', '{cluster:view}', '{cluster}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		SELECT 't1', 'cluster', 'c' || i, 'user', 'u', r FROM generate_series(1, 20) i, unnest('{custom.viewer,custom.other}'::text[]) r`); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.roles", rbac.User, "admin"))
	admin := h.as(t, "admin")
	h.hold(t, "admin", "level:high", "comp:alpha", "comp:bravo", "rel:usa", "rel:gbr", "rel:fra")
	if err := h.authz.DeleteRole(ctx, admin, "t1", "custom.viewer"); err != nil {
		t.Fatal(err)
	}
	if asked != 0 {
		t.Errorf("deleting a role by one cleared for every label asked Config.ResourceOf about %d clusters", asked)
	}
	meanwhile = func(ctx context.Context) error {
		return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(rbac.TenantRoot("t1"), "rel.fra", rbac.User, "admin")})
	}
	if err := h.authz.DeleteRole(ctx, admin, "t1", "custom.other"); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("deleting a role once the actor lost a label value meanwhile: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("the label value should have been revoked meanwhile")
	}
	// Tried again, it asks the host about each scope, whose labels ask nothing of it.
	if err := h.authz.DeleteRole(ctx, admin, "t1", "custom.other"); err != nil || asked != 20 {
		t.Fatalf("deleting it again asked about %d clusters: %v", asked, err)
	}
}

// A removal is refused when, while the scopes its group holds access on are read from the host,
// the group is granted a role on a labeled one, whose label it didn't check.
func TestAGrantToAGroupMadeWhileARemovalIsCheckedIsTriedAgain(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	var meanwhile func(ctx context.Context) error
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if do := meanwhile; do != nil && s == workspace.Scope() {
				meanwhile = nil
				if err := do(ctx); err != nil {
					return rbac.Resource{}, err
				}
			}
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"), grant(workspace.Scope(), "workspace.admin", rbac.Group, "crew"))
	h.join(t, "u")
	if err := h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "crew", Principal: identity("u")}}); err != nil {
		t.Fatal(err)
	}
	meanwhile = func(ctx context.Context) error {
		return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(secret.Scope(), "cluster.login", rbac.Group, "crew")})
	}
	if err := h.authz.ChangeMembers(ctx, h.as(t, "admin"), "t1", nil, []rbac.Member{{Group: "crew", Principal: identity("u")}}); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a removal from a group granted on a labeled scope meanwhile: %v", err)
	}
	if meanwhile != nil {
		t.Fatal("crew should have been granted on the cluster meanwhile")
	}
}

func TestARemovalIsNeverRefusedForAnExclusiveConflict(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) {
		banks(c)
		c.Labels[len(c.Labels)-1].Exclusive = false
	})
	ctx := t.Context()
	h.as(t, "ann")
	h.hold(t, "ann", "bank:a", "bank:b")
	h.groups(t, "approvers")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
		VALUES ('t1', 'tenant', 't1', 'user', 'ann', 'bank.c', 3600, '{group:approvers,user:boss}')`); err != nil {
		t.Fatal(err)
	}
	cfg := h.cfg
	cfg.Labels = slices.Clone(cfg.Labels)
	cfg.Labels[len(cfg.Labels)-1].Exclusive = true
	authz, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Taking the group out of the approvers rewrites the eligibility, as no change that gives.
	if err := authz.DeleteGroups(ctx, host, "t1", []string{"approvers"}); err != nil {
		t.Fatalf("deleting a group a conflicted identity's eligibility names: %v", err)
	}
}

// Making a place or a membership end sooner, or a member a guest, is a removal, never refused for an
// exclusive conflict, as removing it isn't, and changing only a note no change; making one last
// longer, or a guest a member, is not.
func TestShorteningAConflictedIdentitysPlaceOrMembershipIsNeverRefused(t *testing.T) {
	h := labeled(t, func(c *rbac.Config) {
		banks(c)
		c.Labels[len(c.Labels)-1].Exclusive = false
		c.Catalog = append(slices.Clone(c.Catalog), groupMembers)
	})
	ctx := t.Context()
	h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "admin"))
	h.as(t, "ann", "crew")
	h.hold(t, "ann", "bank:a", "bank:b")
	cfg := h.cfg
	cfg.Labels = slices.Clone(cfg.Labels)
	cfg.Labels[len(cfg.Labels)-1].Exclusive = true
	authz, err := rbac.New(h.pool, cfg)
	if err != nil {
		t.Fatal(err)
	}
	admin := h.as(t, "admin")
	place := func(until time.Duration) []rbac.Member {
		return []rbac.Member{{Group: "crew", Principal: identity("ann"), ExpiresAt: h.now.Add(until)}}
	}
	if err := authz.ImportMembers(ctx, host, "t1", place(2*time.Hour)); err != nil {
		t.Errorf("ImportMembers making ann's place end sooner: %v", err)
	}
	if err := authz.ChangeMembers(ctx, admin, "t1", place(time.Hour), nil); err != nil {
		t.Errorf("ChangeMembers making ann's place end sooner: %v", err)
	}
	// Changing only its note gains nothing either.
	noted := place(time.Hour)
	noted[0].Note = "on call"
	if err := authz.ChangeMembers(ctx, admin, "t1", noted, nil); err != nil {
		t.Errorf("ChangeMembers changing the note of ann's place: %v", err)
	}
	noted[0].Note = "rotated"
	if err := authz.ImportMembers(ctx, host, "t1", noted); err != nil {
		t.Errorf("ImportMembers changing the note of ann's place: %v", err)
	}
	membership := func(until time.Duration, note string) []rbac.Membership {
		return []rbac.Membership{{Principal: identity("ann"), ExpiresAt: h.now.Add(until), Note: note}}
	}
	if err := authz.SetMemberships(ctx, host, "t1", membership(24*time.Hour, "")); err != nil {
		t.Errorf("SetMemberships making ann's membership end sooner: %v", err)
	}
	if err := authz.SetMemberships(ctx, host, "t1", membership(24*time.Hour, "contractor")); err != nil {
		t.Errorf("SetMemberships changing the note of ann's membership: %v", err)
	}
	moved := membership(24*time.Hour, "contractor")
	moved[0].Source = "hr"
	if err := authz.SetMemberships(ctx, host, "t1", moved); err != nil {
		t.Errorf("SetMemberships changing the source of ann's membership: %v", err)
	}
	moved[0].Guest = true
	if err := authz.SetMemberships(ctx, host, "t1", moved); err != nil {
		t.Errorf("SetMemberships making ann a guest: %v", err)
	}
	moved[0].Guest = false
	excluded(t, authz.SetMemberships(ctx, host, "t1", moved))
	excluded(t, authz.ImportMembers(ctx, host, "t1", place(3*time.Hour)))
	excluded(t, authz.ChangeMembers(ctx, admin, "t1", place(3*time.Hour), nil))
	excluded(t, authz.SetMemberships(ctx, host, "t1", membership(48*time.Hour, "")))
	if err := authz.ChangeMembers(ctx, admin, "t1", nil, place(0)); err != nil {
		t.Errorf("removing ann's place: %v", err)
	}
}

func TestSuspendingAMemberLiftsNoDeny(t *testing.T) {
	viewer := rbac.RoleDefinition{ID: "cluster.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}, Public: true}
	h := setup(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), viewer, guardRole) })
	ctx := t.Context()
	resources := hostTable(t, h)
	h.seed(t, grant(cluster.Scope(), "cluster.viewer", rbac.Public, ""), grant(cluster.Scope(), "guard", rbac.User, "guardian"))
	guardian := h.as(t, "guardian")
	for _, d := range []rbac.Deny{
		{ID: "contractors", Principals: []rbac.Principal{groupOf("contractors")}, Permissions: []rbac.Permission{view}},
		{ID: "members", Principals: []rbac.Principal{rbac.TenantMembers("t1")}, Exempt: []rbac.Principal{groupOf("staff")}, Permissions: []rbac.Permission{view}},
	} {
		h.groups(t, slices.Collect(func(yield func(string) bool) {
			for _, p := range slices.Concat(d.Principals, d.Exempt) {
				if p.Kind == rbac.Group && !yield(p.ID) {
					return
				}
			}
		})...)
		if err := h.authz.SetDeny(ctx, guardian, cluster, d); err != nil {
			t.Fatal(err)
		}
	}
	for name, s := range map[string]rbac.Subject{"a contractor": h.as(t, "contractor", "contractors"), "a member": h.as(t, "member")} {
		if allowed(t, h, s, view, cluster) {
			t.Fatalf("%s before its suspension", name)
		}
		if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET suspended = true WHERE tenant = 't1' AND principal = $1`, string(s.Principal.Kind)+":"+s.Principal.ID); err != nil {
			t.Fatal(err)
		}
		if allowed(t, h, s, view, cluster) {
			t.Errorf("%s once suspended, by the public's grant", name)
		}
		if d, err := h.authz.Explain(ctx, s, view, cluster); err != nil || d.Allowed {
			t.Errorf("Explain for %s once suspended = %+v, %v", name, d, err)
		}
		listingsAgree(t, h, resources, s, view)
	}
	// An exemption through a group a suspended identity is in lifts nothing either.
	staff := h.as(t, "staffer", "staff")
	if !allowed(t, h, staff, view, cluster) {
		t.Fatal("a member exempt through its group")
	}
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET suspended = true WHERE tenant = 't1' AND principal = 'user:staffer'`); err != nil {
		t.Fatal(err)
	}
	if allowed(t, h, staff, view, cluster) {
		t.Error("a suspended identity exempt through its group")
	}
	listingsAgree(t, h, resources, staff, view)
}

func TestRedefiningARoleGrantedOnALabeledScopeNeedsItsLabel(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), r.ID, rbac.User, "pilot"))
	widened := r
	widened.Permissions = []rbac.Permission{view, login}
	if err := h.authz.SetRole(ctx, admin, "t1", widened); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("widening a role granted on a labeled scope without its label: %v", err)
	}
	if err := h.authz.DeleteRole(ctx, admin, "t1", r.ID); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("deleting a role granted on a labeled scope without its label: %v", err)
	}
	h.hold(t, "admin", "level:high")
	if err := h.authz.SetRole(ctx, admin, "t1", widened); err != nil {
		t.Fatalf("with its label: %v", err)
	}
}

// A role's name and description are its definition's, which the power to define it governs, not
// the data its grants are on: an actor the label of the scope a role is granted on refuses, or a
// deny on that scope's path keeps from changing grants there, renames it and rewrites its
// description, though it can neither narrow nor delete it, which changes the grants there.
func TestRenamingARoleGrantedWhereTheActorMayNotChangeGrantsNeedsOnlyThePowerToDefineIt(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		c.Catalog = append(c.Catalog, rbac.RoleDefinition{ID: "guard", Permissions: []rbac.Permission{rbac.DenyPermission("workspace")}, ResourceTypes: []string{"workspace"}})
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.viewer", Name: "Viewer", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), r.ID, rbac.User, "pilot"), grant(rbac.TenantRoot("t1"), "guard", rbac.User, "guardian"))
	narrowed := r
	narrowed.Permissions = []rbac.Permission{view}
	stopped := func(why string) {
		t.Helper()
		if err := h.authz.SetRole(ctx, admin, "t1", narrowed); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("narrowing the role where %s: %v", why, err)
		}
		if err := h.authz.DeleteRole(ctx, admin, "t1", r.ID); !errors.Is(err, rbac.ErrDenied) {
			t.Errorf("deleting the role where %s: %v", why, err)
		}
		r.Name, r.Description = "Viewer "+why, "Renamed where "+why
		if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
			t.Errorf("renaming the role where %s: %v", why, err)
		}
	}
	stopped("the label refuses the actor")
	if err := h.authz.SetDeny(ctx, h.as(t, "guardian"), workspace, rbac.Deny{ID: "freeze", Permissions: []rbac.Permission{grantC}, Principals: []rbac.Principal{admin.Principal}}); err != nil {
		t.Fatal(err)
	}
	h.hold(t, "admin", "level:high")
	stopped("a deny stops the actor changing grants")
	roles, err := h.authz.CustomRoles(ctx, "t1")
	if err != nil || len(roles) != 1 || roles[0].Name != r.Name || roles[0].Description != r.Description || !slices.Equal(roles[0].Permissions, []rbac.Permission{login, view}) {
		t.Errorf("CustomRoles = %+v, %v", roles, err)
	}
}

// A role granted on a labeled cluster that lists another lets its holders grant that one there, so
// widening it hands more on there: an actor the label refuses can't.
func TestWideningARoleThatOneGrantedOnALabeledScopeListsNeedsItsLabel(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	l := rbac.RoleDefinition{ID: "custom.lister", Permissions: []rbac.Permission{grantC}, ResourceTypes: []string{"cluster"}, GrantableRoles: []rbac.Role{r.ID}}
	for _, d := range []rbac.RoleDefinition{r, l} {
		if err := h.authz.SetRole(ctx, admin, "t1", d); err != nil {
			t.Fatal(err)
		}
	}
	h.seed(t, grant(secret.Scope(), l.ID, rbac.User, "pilot"))
	widened := r
	widened.Permissions = []rbac.Permission{view, login}
	if err := h.authz.SetRole(ctx, admin, "t1", widened); !errors.Is(err, rbac.ErrDenied) {
		t.Errorf("widening a role that one granted on a labeled scope lists, without its label: %v", err)
	}
	h.hold(t, "admin", "level:high")
	if err := h.authz.SetRole(ctx, admin, "t1", widened); err != nil {
		t.Fatalf("with its label: %v", err)
	}
}

// Where the actor's label values satisfy every label, widening a role asks the host nothing about
// the scopes it, or a role listing it, is granted on, and is tried again where they no longer do
// once it holds the tenant's lock.
func TestWideningARoleByOneClearedForEveryLabelAsksTheHostNothingAboutItsScopes(t *testing.T) {
	for _, on := range []string{"custom.viewer", "custom.lister"} {
		t.Run(on, func(t *testing.T) {
			asked := 0
			var meanwhile func(context.Context) error
			h := labeled(t, func(c *rbac.Config) {
				resourceOf := c.ResourceOf
				c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
					if s.Type == "cluster" {
						asked++
					}
					return resourceOf(ctx, tenant, s)
				}
				c.Constraints = []rbac.Constraint{{Name: "meanwhile", Deny: func(ctx context.Context, _ rbac.DB, in rbac.ConstraintInput) (bool, error) {
					if do := meanwhile; do != nil && in.Permission == "rel:fra" {
						meanwhile = nil
						return false, do(ctx)
					}
					return false, nil
				}}}
			})
			ctx := t.Context()
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, grantable_roles)
				VALUES ('t1', 'custom.viewer', '{cluster:view}', '{cluster}', '{}'),
				  ('t1', 'custom.lister', '{cluster:grant}', '{cluster}', '{custom.viewer}')`); err != nil {
				t.Fatal(err)
			}
			if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
				SELECT 't1', 'cluster', 'c' || i, 'user', 'u', $1 FROM generate_series(1, 20) i`, on); err != nil {
				t.Fatal(err)
			}
			tenant := rbac.TenantRoot("t1")
			h.seed(t, grant(tenant, "tenant.roles", rbac.User, "admin"), grant(tenant, "cluster.admin", rbac.User, "admin"))
			admin := h.as(t, "admin")
			h.hold(t, "admin", "level:high", "comp:alpha", "comp:bravo", "rel:usa", "rel:gbr", "rel:fra")
			r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view, login}, ResourceTypes: []string{"cluster"}}
			if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
				t.Fatal(err)
			}
			if asked != 0 {
				t.Errorf("widening a role by one cleared for every label asked Config.ResourceOf about %d clusters", asked)
			}
			meanwhile = func(ctx context.Context) error {
				return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{grant(tenant, "rel.fra", rbac.User, "admin")})
			}
			r.Permissions = []rbac.Permission{view, login, root}
			if err := h.authz.SetRole(ctx, admin, "t1", r); !errors.Is(err, rbac.ErrConflict) {
				t.Fatalf("widening a role once the actor lost a label value meanwhile: %v", err)
			}
			if meanwhile != nil {
				t.Fatal("the label value should have been revoked meanwhile")
			}
			// Tried again, it asks the host about each scope, whose labels ask nothing of it.
			if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil || asked != 20 {
				t.Fatalf("widening it again asked about %d clusters: %v", asked, err)
			}
		})
	}
}

func TestASuspendedMembersGroupsCountTowardTwoExclusiveValues(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	root := rbac.TenantRoot("t1")
	h.as(t, "ann", "a-team")
	h.seed(t, grant(root, "bank.a", rbac.Group, "a-team"))
	if _, err := h.pool.Exec(ctx, `UPDATE rbac_memberships SET suspended = true WHERE tenant = 't1' AND principal = 'user:ann'`); err != nil {
		t.Fatal(err)
	}
	excluded(t, h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(root, "bank.b", rbac.User, "ann")}))
}

// Every change that asks the host about grants is tried again when the memberships its answers
// rest on change between the asking and the change.
func TestAChangeWhoseHostsAnswerRestsOnAChangedMembershipIsTriedAgain(t *testing.T) {
	asGuest := func(h *harness, id string) func(context.Context) error {
		return func(ctx context.Context) error {
			return h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity(id), Guest: true}})
		}
	}
	for _, c := range []struct {
		name  string
		via   rbac.Via
		setup func(*testing.T, *harness) (meanwhile func(context.Context) error, change func(context.Context) error)
	}{
		{"Import", rbac.ViaImport, func(t *testing.T, h *harness) (func(context.Context) error, func(context.Context) error) {
			t.Helper()
			h.join(t, "u")
			return func(ctx context.Context) error { return h.authz.DeletePrincipal(ctx, host, "t1", identity("u")) },
				func(ctx context.Context) error {
					return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.sudo", rbac.User, "u")})
				}
		}},
		{"ImportMembers", rbac.ViaMembership, func(t *testing.T, h *harness) (func(context.Context) error, func(context.Context) error) {
			t.Helper()
			h.join(t, "u")
			h.seed(t, grant(cluster.Scope(), "cluster.sudo", rbac.Group, "admins"))
			return asGuest(h, "u"), func(ctx context.Context) error {
				return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "admins", Principal: identity("u")}})
			}
		}},
		{"ChangeMembers", rbac.ViaMembership, func(t *testing.T, h *harness) (func(context.Context) error, func(context.Context) error) {
			t.Helper()
			h.join(t, "u")
			h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"))
			return asGuest(h, "u"), func(ctx context.Context) error {
				return h.authz.ChangeMembers(ctx, h.as(t, "manager"), "t1", []rbac.Member{{Group: "admins", Principal: identity("u")}}, nil)
			}
		}},
		{"SetRole", rbac.ViaRedefinition, func(t *testing.T, h *harness) (func(context.Context) error, func(context.Context) error) {
			t.Helper()
			admin := roleAdmin(t, h)
			r := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
			if err := h.authz.SetRole(t.Context(), admin, "t1", r); err != nil {
				t.Fatal(err)
			}
			h.seed(t, grant(cluster.Scope(), r.ID, rbac.Group, "ops"))
			h.join(t, "g1")
			r.Permissions = []rbac.Permission{view, login}
			return func(ctx context.Context) error {
					return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity("g1")}})
				}, func(ctx context.Context) error {
					return h.authz.SetRole(ctx, admin, "t1", r)
				}
		}},
		{"Activate", rbac.ViaActivation, func(t *testing.T, h *harness) (func(context.Context) error, func(context.Context) error) {
			t.Helper()
			u := h.as(t, "u")
			if err := h.authz.SetEligibility(t.Context(), h.as(t, "owner"), cluster, rbac.Eligibility{Role: "cluster.sudo", Principal: u.Principal, MaxDuration: time.Hour}); err != nil {
				t.Fatal(err)
			}
			return asGuest(h, "u"), func(ctx context.Context) error {
				_, err := h.authz.Activate(ctx, u, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"})
				return err
			}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var meanwhile func(context.Context) error
			h := meanwhileAsked(t, c.via, &meanwhile)
			do, change := c.setup(t, h)
			meanwhile = do
			if err := change(t.Context()); !errors.Is(err, rbac.ErrConflict) {
				t.Fatalf("a membership the host's answer rests on changed meanwhile: %v", err)
			}
		})
	}
}

func TestAMembershipTheHostWasNotAskedAboutChangingIsNoConflict(t *testing.T) {
	var meanwhile func(context.Context) error
	h := meanwhileAsked(t, rbac.ViaMembership, &meanwhile)
	ctx := t.Context()
	h.join(t, "u", "v")
	h.groups(t, "everyone")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"))
	// v joins a group that holds nothing, so the host is asked nothing about it.
	meanwhile = func(ctx context.Context) error {
		return h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("v"), Guest: true}})
	}
	add := []rbac.Member{{Group: "admins", Principal: identity("u")}, {Group: "everyone", Principal: identity("v")}}
	if err := h.authz.ImportMembers(ctx, host, "t1", add); err != nil {
		t.Fatalf("a member of a group holding nothing became a guest while the host was asked about another: %v", err)
	}
}

func TestARedefinitionWhoseGrantWasRevokedWhileTheHostWasAskedIsNoConflict(t *testing.T) {
	var meanwhile func(context.Context) error
	h := meanwhileAsked(t, rbac.ViaRedefinition, &meanwhile)
	ctx := t.Context()
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.op", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
		t.Fatal(err)
	}
	h.join(t, "u")
	g := grant(cluster.Scope(), r.ID, rbac.User, "u")
	h.seed(t, g)
	meanwhile = func(ctx context.Context) error { return h.authz.DeleteGrants(ctx, host, "t1", []rbac.Grant{g}) }
	r.Permissions = []rbac.Permission{view, login}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
		t.Fatalf("widening a role whose grant was revoked while the host was asked: %v", err)
	}
}

func TestAnEndedGrantOnALabeledScopeAsksNothingOfDeletingItsRole(t *testing.T) {
	secret := cluster
	secret.Labels = rbac.Label{"level": {"high"}}
	h := labeled(t, func(c *rbac.Config) {
		resourceOf := c.ResourceOf
		c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
			if s == secret.Scope() {
				return secret, nil
			}
			return resourceOf(ctx, tenant, s)
		}
	})
	ctx := t.Context()
	admin := roleAdmin(t, h)
	r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
	if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
		t.Fatal(err)
	}
	g := grant(cluster.Scope(), r.ID, rbac.User, "pilot")
	g.ExpiresAt = h.now.Add(time.Hour)
	h.seed(t, g)
	h.now = h.now.Add(2 * time.Hour)
	if err := h.authz.DeleteRole(ctx, admin, "t1", r.ID); err != nil {
		t.Fatalf("deleting a role whose only grant on a labeled scope has ended: %v", err)
	}
}

func TestAMembershipReadsTheSameInAnotherTimeZone(t *testing.T) {
	// One connection, so the host's answer and the change's transaction read on the same one,
	// whose time zone the host changes in between.
	h := setupOn(t, pgtest.Open(t, "pool_max_conns=1"), func(c *rbac.Config) {
		validate := c.ValidateGrant
		c.ValidateGrant = func(ctx context.Context, q rbac.DB, in rbac.GrantInput) error {
			if _, err := q.Exec(ctx, `SET TIME ZONE 'Asia/Tokyo'`); err != nil {
				return err
			}
			return validate(ctx, q, in)
		}
	})
	ctx := t.Context()
	if err := h.authz.SetMemberships(ctx, host, "t1", []rbac.Membership{{Principal: identity("u"), ExpiresAt: h.now.Add(time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	sudo := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: identity("u")}}}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, sudo); err != nil {
		t.Fatalf("a grant the host was asked about in one time zone, made in another: %v", err)
	}
}

func TestARoleGrantedOnALabeledScopeWhileItsLabelsWereCheckedIsTriedAgain(t *testing.T) {
	for _, op := range []string{"SetRole", "DeleteRole"} {
		t.Run(op, func(t *testing.T) {
			secret := cluster
			secret.Labels = rbac.Label{"level": {"high"}}
			open := rbac.Scope{Type: "cluster", ID: "c2"}
			var meanwhile func(context.Context) error
			h := labeled(t, func(c *rbac.Config) {
				resourceOf := c.ResourceOf
				c.ResourceOf = func(ctx context.Context, tenant string, s rbac.Scope) (rbac.Resource, error) {
					if s == secret.Scope() {
						return secret, nil
					}
					// Asked about the scope it is granted on, the host grants it on the labeled one.
					if do := meanwhile; s == open && do != nil {
						meanwhile = nil
						if err := do(ctx); err != nil {
							return rbac.Resource{}, err
						}
					}
					return resourceOf(ctx, tenant, s)
				}
			})
			ctx := t.Context()
			admin := roleAdmin(t, h)
			r := rbac.RoleDefinition{ID: "custom.viewer", Permissions: []rbac.Permission{view}, ResourceTypes: []string{"cluster"}}
			if err := h.authz.SetRole(ctx, admin, "t1", r); err != nil {
				t.Fatal(err)
			}
			h.seed(t, grant(open, r.ID, rbac.User, "pilot"))
			meanwhile = func(ctx context.Context) error {
				return h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(secret.Scope(), r.ID, rbac.User, "pilot")})
			}
			change := func() error {
				if op == "DeleteRole" {
					return h.authz.DeleteRole(ctx, admin, "t1", r.ID)
				}
				widened := r
				widened.Permissions = []rbac.Permission{view, login}
				return h.authz.SetRole(ctx, admin, "t1", widened)
			}
			if err := change(); !errors.Is(err, rbac.ErrConflict) {
				t.Fatalf("granted on a labeled scope while its labels were checked: %v", err)
			}
			if err := change(); !errors.Is(err, rbac.ErrDenied) {
				t.Fatalf("tried again: %v", err)
			}
		})
	}
}

func TestAMemberWhoseIDSpellsTwoMembersIsAChangedMembership(t *testing.T) {
	var meanwhile func(context.Context) error
	h := meanwhileAsked(t, rbac.ViaApply, &meanwhile)
	ctx := t.Context()
	if err := h.authz.ImportGroups(ctx, host, "t1", []rbac.GroupDefinition{{ID: "ops"}}); err != nil {
		t.Fatal(err)
	}
	// An id the host can give, which reads as the two members' memberships one after the other.
	both := "a=false false \nuser:b"
	h.join(t, "a", "b", both)
	two := []rbac.Member{{Group: "ops", Principal: identity("a")}, {Group: "ops", Principal: identity("b")}}
	if err := h.authz.ImportMembers(ctx, host, "t1", two); err != nil {
		t.Fatal(err)
	}
	meanwhile = func(ctx context.Context) error {
		if err := h.authz.DeleteMembers(ctx, host, "t1", two); err != nil {
			return err
		}
		return h.authz.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "ops", Principal: identity(both)}})
	}
	sudo := rbac.Change{Grant: []rbac.Binding{{Role: "cluster.sudo", Principal: groupOf("ops")}}}
	if err := h.authz.Apply(ctx, h.as(t, "owner"), cluster, sudo); !errors.Is(err, rbac.ErrConflict) {
		t.Fatalf("a grant to a group whose members were replaced by one spelling them: %v", err)
	}
}

// A change's authority is read with the custom roles its actor's grants name, as of one moment, as
// a check reads them: a grant made and a role narrowed meanwhile can't refuse what no moment did.
func TestAChangesAuthorityIsReadWithItsCustomRolesAsOfOneMoment(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	// Each lets its holder grant cluster.login.
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		VALUES ('t1', 'custom.a', $1, '{cluster}'), ('t1', 'custom.b', $1, '{cluster}')`,
		[]string{string(view), string(login), string(grantC)}); err != nil {
		t.Fatal(err)
	}
	h.seed(t, grant(cluster.Scope(), "custom.a", rbac.User, "lead"))
	lead := h.as(t, "lead")
	h.as(t, "u")
	// Once they are read, the lead is granted b, and then a no longer lets it grant: at every
	// moment, one of them does.
	once := false
	rbac.SetReadingRoles(t, func() {
		if once {
			return
		}
		once = true
		if err := h.authz.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "custom.b", rbac.User, "lead")}); err != nil {
			t.Error(err)
		}
		if _, err := h.pool.Exec(ctx, `UPDATE rbac_roles SET permissions = $1 WHERE id = 'custom.a'`, []string{string(view)}); err != nil {
			t.Error(err)
		}
	})
	if err := h.authz.Apply(ctx, lead, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: identity("u")}}}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !once {
		t.Fatal("the change read its authority without reaching the hook")
	}
}

// What a change rests on is read by the memberships it names, however many others the tenant has
// in its groups.
func TestAChangeReadsTheStandingOfOnlyWhomItNames(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "g1", "g2")
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			SELECT 't1', 'g' || (1 + (random() < 0.5)::int), 'user', id FROM others`, "rbac_members")
	}
	h.as(t, "ann")
	// The pages of memberships and their indexes granting ann a role reads.
	read := func() int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		start := pagesRead(ctx, t, tx, "rbac_memberships")
		if err := h.authz.WithTx(tx).Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.User, "ann")}); err != nil {
			t.Fatal(err)
		}
		return pagesRead(ctx, t, tx, "rbac_memberships") - start
	}
	// Ten times as many others deepen the indexes, which a change reads a few pages more of, but
	// reading every membership would take ten times the pages.
	others(500)
	few := read()
	others(4500)
	if many := read(); many > few*3/2 {
		t.Fatalf("granting ann a role read %d pages of memberships, and %d once 4500 more were members of groups", few, many)
	}
}

// What a change rests on is costed by what it reads, however large the tenant's groups: costed as
// if it read every member, its statement would be compiled each time, which takes longer than
// reading what it names.
func TestAChangeReadsTheStandingOfWhomItNamesWithoutJIT(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "everyone")
	everyone := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			SELECT 't1', 'everyone', 'user', id FROM others`, "rbac_members")
	}
	// Each kind a change doesn't name is sent as NULL, as stand sends it.
	cost := func(identities, groups []string) float64 {
		t.Helper()
		var plan []struct {
			Plan struct {
				Cost float64 `json:"Total Cost"`
			}
		}
		if err := h.pool.QueryRow(ctx, "EXPLAIN (FORMAT JSON) "+rbac.StandSQL, "t1", identities, groups, h.now).Scan(&plan); err != nil {
			t.Fatal(err)
		}
		return plan[0].Plan.Cost
	}
	one := []string{"user:u1"}
	everyone(1500)
	few := cost(one, nil)
	everyone(13500)
	for _, named := range []struct{ identities, groups []string }{{one, nil}, {nil, []string{"everyone"}}} {
		// PostgreSQL's default jit_above_cost.
		if c := cost(named.identities, named.groups); c >= 100000 {
			t.Fatalf("reading the standing of %+v is costed at %.0f, past JIT's threshold", named, c)
		}
	}
	// One identity's is costed alike in a tenant ten times as large: costed by its groups, it would
	// pass JIT's threshold once they are large enough.
	if many := cost(one, nil); many > few*3/2 {
		t.Fatalf("reading the standing of one identity is costed at %.0f, and %.0f once 13500 more were members of a group", few, many)
	}
}

// What a change rests on is read in rows as many as whom it names, whichever plan PostgreSQL
// picks: it costs the memberships a change reaches as ten, so where sorting is dear, as at a
// small work_mem or in a large tenant, and under the generic plan a cached statement moves to, a
// join would compare each member with every membership found, which takes seconds for a group of
// 20,000, under the change's locks.
func TestAChangeReadsTheStandingOfALargeGroupInRowsAsMany(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "g1", "g2")
	const n = 2000
	manyMembers(t, h, 2*n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		SELECT 't1', 'g' || (1 + row_number() OVER () % 2), 'user', id FROM others`, "rbac_members")
	conn, err := h.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SET work_mem = '64kB'; PREPARE stand AS `+rbac.StandSQL); err != nil {
		t.Fatal(err)
	}
	// Each loop's rows, with those its filters removed, as a nested loop can compare each member
	// with every membership in a filter and pass on one.
	type node struct {
		Rows       float64 `json:"Actual Rows"`
		Filtered   float64 `json:"Rows Removed by Filter"`
		JoinFilter float64 `json:"Rows Removed by Join Filter"`
		Loops      float64 `json:"Actual Loops"`
		Plans      []node
	}
	var rows func(node) float64
	rows = func(p node) float64 {
		sum := (p.Rows + p.Filtered + p.JoinFilter) * p.Loops
		for _, c := range p.Plans {
			sum += rows(c)
		}
		return sum
	}
	for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
		var plan []struct{ Plan node }
		if _, err := conn.Exec(ctx, `SET plan_cache_mode = `+mode); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRow(ctx, `EXPLAIN (ANALYZE, FORMAT JSON) EXECUTE stand('t1', NULL, '{g1}', now())`).Scan(&plan); err != nil {
			t.Fatal(err)
		}
		if r := rows(plan[0].Plan); r > 50*n {
			t.Fatalf("reading the standing of a group of %d under %s passed %.0f rows through its plan", n, mode, r)
		}
	}
}

// A small group's members are read alone, however large the tenant's other groups, by a change
// naming it, by Holders and by Holders as of a time: each statement reads the members of the groups
// it reaches planned for those groups' own size.
func TestASmallGroupsMembersAreReadAlone(t *testing.T) {
	h := labeled(t, banks)
	ctx := t.Context()
	h.groups(t, "everyone", "admins")
	for _, id := range []string{"a1", "a2", "a3"} {
		h.as(t, id, "admins")
	}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"))
	// The pages of the members, and of history, that each reads, in a transaction it rolls back.
	read := func(at time.Time) (change, holders, asOf int64) {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		start := pagesRead(ctx, t, tx, "rbac_members")
		if err := h.authz.WithTx(tx).Import(ctx, host, "t1", []rbac.Grant{grant(rbac.TenantRoot("t1"), "bank.a", rbac.Group, "admins")}); err != nil {
			t.Fatal(err)
		}
		mid := pagesRead(ctx, t, tx, "rbac_members")
		if hs, err := h.authz.WithTx(tx).Holders(ctx, login, cluster); err != nil || len(hs) < 3 {
			t.Fatalf("Holders = %+v, %v", hs, err)
		}
		change, holders = mid-start, pagesRead(ctx, t, tx, "rbac_members")-mid
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			start := pagesRead(ctx, t, tx, "rbac_history")
			hs, err := a.Holders(ctx, login, cluster)
			if err == nil && len(hs) < 3 {
				err = fmt.Errorf("Holders as of now = %+v", hs)
			}
			asOf = pagesRead(ctx, t, tx, "rbac_history") - start
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return change, holders, asOf
	}
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			SELECT 't1', 'everyone', 'user', id FROM others`, "rbac_members", "rbac_history")
	}
	// Ten times as many others deepen the indexes, which each reads a few pages more of, but reading
	// every member would take ten times the pages.
	others(500)
	change, holders, asOf := read(dbNow(t, h))
	others(4500)
	moreChange, moreHolders, moreAsOf := read(dbNow(t, h))
	for _, c := range []struct {
		what      string
		few, many int64
	}{{"a change naming it", change, moreChange}, {"Holders", holders, moreHolders}, {"Holders as of a time", asOf, moreAsOf}} {
		if c.many > c.few*3/2 {
			t.Errorf("%s read %d pages, and %d once 4500 more were in another group", c.what, c.few, c.many)
		}
	}
}

// Holders reads, of the members of a large group a deny on the resource names, only the holders,
// now and as of a time: what reads them counts a function's rows as a thousand, and finding the
// holders among every member reads each one.
func TestHoldersReadsOnlyTheHoldersInTheGroupsADenyNames(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "everyone", "admins")
	h.as(t, "a1", "admins", "everyone")
	h.as(t, "a2", "admins")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "admins"))
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
		VALUES ('t1', 'cluster', 'c1', 'd', '{group:everyone}', '{cluster:login}')`); err != nil {
		t.Fatal(err)
	}
	// The pages of the members, and of history, that Holders reads, in a transaction it rolls back.
	read := func(at time.Time) (now, asOf int64) {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		held := func(a *rbac.Authorizer) error {
			hs, err := a.Holders(ctx, login, cluster)
			if ps := holderPrincipals(hs); err == nil && (slices.Contains(ps, rbac.Principal{Kind: rbac.User, ID: "a1"}) ||
				!slices.Contains(ps, rbac.Principal{Kind: rbac.User, ID: "a2"})) {
				err = fmt.Errorf("Holders = %+v", hs)
			}
			return err
		}
		start := pagesRead(ctx, t, tx, "rbac_members")
		if err := held(h.authz.WithTx(tx)); err != nil {
			t.Fatal(err)
		}
		now = pagesRead(ctx, t, tx, "rbac_members") - start
		if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
			start := pagesRead(ctx, t, tx, "rbac_history")
			err := held(a)
			asOf = pagesRead(ctx, t, tx, "rbac_history") - start
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return now, asOf
	}
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			SELECT 't1', 'everyone', 'user', id FROM others`, "rbac_members", "rbac_history")
	}
	others(500)
	now, asOf := read(dbNow(t, h))
	others(4500)
	moreNow, moreAsOf := read(dbNow(t, h))
	for _, c := range []struct {
		what      string
		few, many int64
	}{{"Holders", now, moreNow}, {"Holders as of a time", asOf, moreAsOf}} {
		if c.many > c.few*3/2 {
			t.Errorf("%s read %d pages, and %d once 4500 more were in the group a deny names", c.what, c.few, c.many)
		}
	}
}

// Holders reads the memberships of a large group it lists in no more pages than they fill, now
// and as of a time: what reads them counts a function's rows as a thousand, and would look each
// member's up on its own, which as of a time reads its every version.
func TestHoldersReadsTheMembershipsOfALargeGroupInAsManyPages(t *testing.T) {
	h := setup(t)
	ctx := t.Context()
	h.groups(t, "everyone")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.Group, "everyone"))
	// Only in a tenant this large does the planner, counting a function's rows as a thousand, look
	// each member's membership up on its own: at 5,000 it hashes them.
	const n = 20000
	manyMembers(t, h, n, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		SELECT 't1', 'everyone', 'user', id FROM others`, "rbac_members", "rbac_history")
	// The pages table and its indexes fill.
	filled := func(table string) int64 {
		t.Helper()
		var pages int64
		if err := h.pool.QueryRow(ctx, `SELECT sum(pg_relation_size(oid) / current_setting('block_size')::bigint) FROM pg_class
			WHERE oid = $1::regclass OR oid IN (SELECT indexrelid FROM pg_index WHERE indrelid = $1::regclass)`, table).Scan(&pages); err != nil {
			t.Fatal(err)
		}
		return pages
	}
	at, history := dbNow(t, h), filled("rbac_history")
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	held := func(a *rbac.Authorizer) error {
		hs, err := a.Holders(ctx, login, cluster)
		if err == nil && len(hs) < n {
			err = fmt.Errorf("Holders listed %d of the group's %d", len(hs), n)
		}
		return err
	}
	start := pagesRead(ctx, t, tx, "rbac_memberships")
	if err := held(h.authz.WithTx(tx)); err != nil {
		t.Fatal(err)
	}
	if read, fill := pagesRead(ctx, t, tx, "rbac_memberships")-start, filled("rbac_memberships"); read > 2*fill {
		t.Errorf("Holders read %d pages of memberships that fill %d", read, fill)
	}
	// History as of the time reads each version and whether a later one replaced it.
	if err := h.authz.WithTx(tx).AsOf(ctx, "t1", at, func(a *rbac.Authorizer) error {
		start := pagesRead(ctx, t, tx, "rbac_history")
		err := held(a)
		if read := pagesRead(ctx, t, tx, "rbac_history") - start; err == nil && read > 4*history {
			err = fmt.Errorf("Holders as of a time read %d pages of history that fill %d", read, history)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

// deeper is how many more pages a change or a read of a few rows reads once ten times as many rows
// are beside them, each of its statements descending indexes a level deeper; reading those rows
// would take ten times the pages.
const deeper = 20

// generic is crowded on a pool whose sessions plan every statement as PostgreSQL plans one a
// connection has run five times, generically, costing each index by the tables' averages.
func generic(t *testing.T, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	return crowded(t, pgtest.Open(t, "plan_cache_mode=force_generic_plan"), mutate...)
}

// custom is setup on a pool whose sessions plan every statement for its arguments: at the default
// plan_cache_mode, a statement a connection runs a sixth time can turn generic, as a test that
// repeats a call on a pool's connections does.
func custom(t *testing.T, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	return setupOn(t, pgtest.Open(t, "plan_cache_mode=force_custom_plan"), mutate...)
}

// crowded is setupOn in a database of many small tenants beside t1, where a principal and a scope
// hold a grant or two, a group has a member or two, and a scope has an eligibility and a deny or
// two, which name a group.
func crowded(t *testing.T, pool *pgxpool.Pool, mutate ...func(*rbac.Config)) *harness {
	t.Helper()
	h := setupOn(t, pool, mutate...)
	for _, q := range []string{
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		 SELECT 's' || j, 'cluster', 'c' || i, 'user', 'u' || j || '-' || i, 'cluster.admin' FROM generate_series(1, 2000) j, generate_series(1, 10) i`,
		`INSERT INTO rbac_groups (tenant, id) SELECT 's' || j, 'g' || i FROM generate_series(1, 2000) j, generate_series(1, 3) i`,
		`INSERT INTO rbac_memberships (tenant, principal_kind, principal_id)
		 SELECT 's' || j, 'user', 'u' || j || '-' || i FROM generate_series(1, 2000) j, generate_series(1, 3) i`,
		`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		 SELECT 's' || j, 'g' || i, 'user', 'u' || j || '-' || i FROM generate_series(1, 2000) j, generate_series(1, 3) i`,
		`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
		 SELECT 's' || j, 'cluster', 'c' || i, 'user', 'u' || j || '-' || i, 'cluster.sudo', 3600, ARRAY['group:g' || i]
		 FROM generate_series(1, 2000) j, generate_series(1, 2) i`,
		`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		 SELECT 's' || j, 'cluster', 'c' || i, 'd', ARRAY['group:g' || i], ARRAY['user:u' || j || '-' || i], '{cluster:root}'
		 FROM generate_series(1, 2000) j, generate_series(1, 2) i`,
	} {
		if _, err := h.pool.Exec(t.Context(), q); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

// A check, a list of what a subject may do and a change's authority read, of the grants, only the
// subject's principals' on the path under a generic plan, and of the groups, only its own, as
// GroupsOf reads them and as a change reads an actor's in a nested group: there an index leading to
// a scope or a principal alone looks as cheap as the key index, and would read every grant on a busy
// tenant, or of a group granted on every cluster; and the groups a group is in, joined to the
// tenant's members, would read every one.
func TestChecksUnderAGenericPlanReadOnlyTheirSubjectsGrants(t *testing.T) {
	h := generic(t)
	ctx := t.Context()
	h.groups(t, "builders", "everyone")
	ann := h.as(t, "ann", "inner")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'builders', 'group', 'inner')`); err != nil {
		t.Fatal(err)
	}
	owner := rbac.Subject{Principal: rbac.Principal{Kind: rbac.User, ID: "owner"}}
	h.as(t, owner.Principal.ID)
	boss := h.as(t, "boss", "inner")
	sudo := grant(cluster.Scope(), "cluster.sudo", rbac.Group, "builders")
	sudo.Condition = rbac.Condition{Expression: `subject.id == "ann"`}
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "ann"), sudo, grant(cluster.Scope(), "cluster.admin", rbac.User, "boss"))
	// The pages of the grants and the members, and their indexes, each reads, in a transaction it
	// rolls back.
	read := func() map[string]int64 {
		t.Helper()
		pages := map[string]int64{}
		for what, f := range map[string]func(a *rbac.Authorizer) error{
			"Authorize":                   func(a *rbac.Authorizer) error { return a.Authorize(ctx, ann, login, cluster) },
			"Authorize under a condition": func(a *rbac.Authorizer) error { return a.Authorize(ctx, ann, root, cluster) },
			"Permissions":                 func(a *rbac.Authorizer) error { return second(a.Permissions(ctx, ann, cluster)) },
			"Permissions on the tenant":   func(a *rbac.Authorizer) error { return second(a.Permissions(ctx, ann, tenantT1)) },
			"Grantable":                   func(a *rbac.Authorizer) error { return second(a.Grantable(ctx, owner, cluster)) },
			"Apply": func(a *rbac.Authorizer) error {
				return a.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: ann.Principal}}})
			},
			// Granted again as it is stored, which the change looks up by its whole key.
			"Apply under a condition": func(a *rbac.Authorizer) error {
				return a.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{sudo.Binding}})
			},
			"Grantable in a nested group": func(a *rbac.Authorizer) error { return second(a.Grantable(ctx, boss, cluster)) },
			"Apply in a nested group": func(a *rbac.Authorizer) error {
				return a.Apply(ctx, boss, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: owner.Principal}}})
			},
			"GroupsOf": func(a *rbac.Authorizer) error { return second(a.GroupsOf(ctx, "t1", ann.Principal)) },
		} {
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				for _, table := range []string{"rbac_grants", "rbac_members"} {
					pages[what+" of "+table] -= pagesRead(ctx, t, tx, table)
				}
				if err := f(h.authz.WithTx(tx)); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				for _, table := range []string{"rbac_grants", "rbac_members"} {
					pages[what+" of "+table] += pagesRead(ctx, t, tx, table)
				}
			}()
		}
		return pages
	}
	// Others hold a role on the tenant and are in another group, and builders hold one on each of
	// as many clusters.
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `, members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
			  SELECT 't1', 'everyone', 'user', id FROM others)
			INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'tenant', 't1', 'user', id, 'cluster.login' FROM others
			UNION ALL SELECT 't1', 'cluster', id, 'group', 'builders', 'cluster.login' FROM others`, "rbac_grants", "rbac_members")
	}
	others(500)
	few := read()
	others(4500)
	for what, many := range read() {
		if many > few[what]*3/2+deeper {
			t.Errorf("%s read %d pages, and %d once 4500 more were on the tenant, in another group and builders'", what, few[what], many)
		}
	}
}

// A check reads its subject's grants from an index alone, under a generic plan too: a plan picks
// the narrower indexes leading to a scope or to a principal over the key, so they hold what a check
// reads, as the key does, or it would read each grant's row, which grants made at different times
// have on pages of their own.
func TestChecksReadTheirGrantsFromAnIndexAlone(t *testing.T) {
	for _, plan := range []string{"custom", "generic"} {
		t.Run(plan, func(t *testing.T) {
			var h *harness
			if plan == "generic" {
				h = generic(t)
			} else {
				h = setup(t)
			}
			ctx := t.Context()
			ann := h.as(t, "ann", "builders")
			held := 0
			for _, s := range []rbac.Scope{cluster.Scope(), {Type: "workspace", ID: "w1"}, {Type: "org", ID: "o1"}, rbac.TenantRoot("t1")} {
				for _, r := range []rbac.Role{"cluster.login", "cluster.sudo", "cluster.admin"} {
					h.seed(t, grant(s, r, rbac.User, "ann"), grant(s, r, rbac.Group, "builders"))
					held += 2
					manyMembers(t, h, 300, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
						SELECT 't1', 'tenant', 't1', 'user', id, 'cluster.login' FROM others`, "rbac_grants")
				}
			}
			// So the visibility map lets a scan of an index skip the rows. VACUUM marks none visible to
			// all while an older snapshot elsewhere in the database, such as another run's, is open.
			for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(time.Second) {
				if _, err := h.pool.Exec(ctx, `VACUUM rbac_grants`); err != nil {
					t.Fatal(err)
				}
				var visible bool
				if err := h.pool.QueryRow(ctx, `SELECT relallvisible >= relpages FROM pg_class WHERE oid = 'rbac_grants'::regclass`).Scan(&visible); err != nil {
					t.Fatal(err)
				}
				if visible {
					break
				}
				if time.Now().After(deadline) {
					t.Skip("an older snapshot elsewhere in the database keeps rbac_grants' rows from being visible to all")
				}
			}
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			// The pages of the table itself, not its indexes: its rows and its visibility map.
			rows := func() int64 {
				t.Helper()
				var n int64
				if err := tx.QueryRow(ctx, `SELECT pg_stat_get_xact_blocks_fetched('rbac_grants'::regclass)`).Scan(&n); err != nil {
					t.Fatal(err)
				}
				return n
			}
			start := rows()
			if err := h.authz.WithTx(tx).Authorize(ctx, ann, login, cluster); err != nil {
				t.Fatal(err)
			}
			if read := rows() - start; read > int64(held/4) {
				t.Errorf("a check of a subject holding %d grants read %d pages of the table's rows", held, read)
			}
		})
	}
}

// Filter, its condition in the host's query, and Reachable read, of the grants, only the subject's
// principals' on scopes of the types a resource's path holds, a type at a time, under a generic plan
// too: of a range of each type's scopes, a plan can seek only one, and reading every grant of the
// principals instead reads a group's on thousands of resources of another type; and a range of
// every tenant's grants on clusters, by the scope alone, looks as cheap as the subject's.
func TestListingsUnderAGenericPlanReadOnlyTheirSubjectsGrants(t *testing.T) {
	volumes := rbac.RoleDefinition{ID: "volume.admin", Permissions: []rbac.Permission{"volume:view"}, ResourceTypes: []string{"volume"}}
	h := generic(t, func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), volumes) })
	ctx := t.Context()
	hostTable(t, h)
	ann := h.as(t, "ann", "builders")
	h.seed(t, grant(cluster.Scope(), "cluster.login", rbac.User, "ann"))
	read := func() map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		a := h.authz.WithTx(tx)
		var pred rbac.Predicate
		pages := map[string]int64{}
		for _, c := range []struct {
			what string
			f    func() error
		}{
			{"Filter", func() (err error) {
				pred, err = a.Filter(ctx, ann, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
				return err
			}},
			{"Filter's condition", func() error {
				var n int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM clusters WHERE `+pred.SQL, pred.Args...).Scan(&n); err != nil || n != 1 {
					return fmt.Errorf("listed %d, %w", n, err)
				}
				return nil
			}},
			{"Reachable", func() error { return second(a.Reachable(ctx, ann, login, "t1", "cluster")) }},
		} {
			start := pagesRead(ctx, t, tx, "rbac_grants")
			if err := c.f(); err != nil {
				t.Fatalf("%s: %v", c.what, err)
			}
			pages[c.what] = pagesRead(ctx, t, tx, "rbac_grants") - start
		}
		return pages
	}
	// Others hold a role on a cluster each, and builders one on each of as many volumes.
	others := func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', id, 'user', id, 'cluster.login' FROM others
			UNION ALL SELECT 't1', 'volume', id, 'group', 'builders', 'volume.admin' FROM others`, "rbac_grants")
	}
	others(500)
	few := read()
	others(4500)
	for what, many := range read() {
		if many > few[what]*3/2+deeper {
			t.Errorf("%s read %d pages of grants, and %d once 4500 more were on clusters and builders' on volumes", what, few[what], many)
		}
	}
}

// customSearches are Filter, Reachable and Holders by u on c0 of the host's table, each with what it
// read of rbac_grants, on a's transaction tx.
func customSearches(ctx context.Context, t *testing.T, tx pgx.Tx, a *rbac.Authorizer, u rbac.Subject, c0 rbac.Resource) map[string]int64 {
	t.Helper()
	pages := map[string]int64{}
	for what, f := range map[string]func() error{
		"Filter": func() error {
			return second(a.Filter(ctx, u, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1))
		},
		"Reachable": func() error { return second(a.Reachable(ctx, u, login, "t1", "cluster")) },
		"Holders": func() error {
			hs, err := a.Holders(ctx, login, c0)
			if err == nil && !slices.Equal(holderPrincipals(hs), []rbac.Principal{u.Principal}) {
				err = fmt.Errorf("Holders = %+v", hs)
			}
			return err
		},
	} {
		start := pagesRead(ctx, t, tx, "rbac_grants")
		if err := f(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		pages[what] = pagesRead(ctx, t, tx, "rbac_grants") - start
	}
	return pages
}

// grantedCustomly is h with the host's table, u holding login on its c0, and a custom role giving
// login on clusters that n others hold, each on a cluster of its own, as others grants more.
func grantedCustomly(t *testing.T, h *harness, n int) (u rbac.Subject, c0 rbac.Resource, others func(n int)) {
	t.Helper()
	resources := hostTable(t, h)
	u = h.as(t, "u")
	h.seed(t, grant(resources[0].Scope(), "cluster.login", rbac.User, "u"))
	if _, err := h.pool.Exec(t.Context(), `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		VALUES ('t1', 'custom.view', '{cluster:view,cluster:login}', '{cluster}')`); err != nil {
		t.Fatal(err)
	}
	others = func(n int) {
		t.Helper()
		manyMembers(t, h, n, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			SELECT 't1', 'cluster', id, 'user', id, 'custom.view' FROM others`, "rbac_grants")
	}
	others(n)
	return u, resources[0], others
}

// Filter, Reachable and Holders read, of the grants of custom roles, only the public's and the
// tenant's members' on the scopes they read, which of those roles give through them, under a
// generic plan too: tested for the custom prefix as they were read, the grants were read by the
// custom roles' index on the tenant alone, which a generic plan costs as an average tenant's few,
// so each search read every grant of a custom role in the tenant, once for each type or scope.
func TestSearchesUnderAGenericPlanReadOnlyTheBroadGrantsOfCustomRoles(t *testing.T) {
	h := generic(t)
	ctx := t.Context()
	u, c0, others := grantedCustomly(t, h, 500)
	read := func() map[string]int64 {
		t.Helper()
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		return customSearches(ctx, t, tx, h.authz.WithTx(tx), u, c0)
	}
	few := read()
	others(4500)
	for what, many := range read() {
		if many > few[what]*3/2+deeper {
			t.Errorf("%s read %d pages of grants, and %d once 4500 more held a custom role on clusters", what, few[what], many)
		}
	}
}

// At the default plan_cache_mode, a connection that has run a search five times reads no more on its
// sixth, in a tenant whose members and the public hold custom roles on thousands of scopes: there
// PostgreSQL planned which custom roles those grants name generically, by the custom roles' index
// on the tenant alone, and read every grant of one in the tenant, once for each type.
func TestSearchesReadAsMuchOnceAConnectionPlansThemGenerically(t *testing.T) {
	h := crowded(t, pgtest.Open(t, "pool_max_conns=1"))
	ctx := t.Context()
	c0 := hostTable(t, h)[0]
	u := h.as(t, "u")
	h.seed(t, grant(c0.Scope(), "cluster.login", rbac.User, "u"))
	for _, q := range []string{
		`INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		  SELECT 't1', 'custom.r' || i, '{cluster:view,cluster:login}', '{cluster}' FROM generate_series(1, 300) i`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		  SELECT 't1', 'cluster', 'k' || i, 'members', 't1', 'custom.r' || (i % 300 + 1) FROM generate_series(1, 3000) i`,
		`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
		  SELECT 't1', 'workspace', 'ws' || i, 'public', '', 'custom.r' || (i % 300 + 1) FROM generate_series(1, 3000) i`,
		`ANALYZE rbac_grants, rbac_roles`,
	} {
		if _, err := h.pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	var first map[string]int64
	for run := range 8 {
		func() {
			tx, err := h.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			pages := customSearches(ctx, t, tx, h.authz.WithTx(tx), u, c0)
			if first == nil {
				first = pages
			}
			for what, n := range pages {
				if n > first[what]*3/2+deeper {
					t.Errorf("%s read %d pages of grants on its first run on a connection, and %d on run %d", what, first[what], n, run+1)
				}
			}
		}()
	}
}

// Filter's count of the grants that pick its form stops a little past where the form changes,
// however many of a built-in role its subject holds, and beside a grant of a custom role read
// before them: counted with the custom roles the grants name, which it reads from every one, the
// count read all of them, as many as the condition then reads.
func TestFilterCountsAFewOfItsSubjectsGrantsOfBuiltInRoles(t *testing.T) {
	h := crowded(t, pgtest.Open(t, ""))
	ctx := t.Context()
	c0 := hostTable(t, h)[0]
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types)
		VALUES ('t1', 'custom.login', '{cluster:view,cluster:login}', '{cluster}')`); err != nil {
		t.Fatal(err)
	}
	for _, plan := range []string{"force_custom_plan", "force_generic_plan"} {
		for _, custom := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s custom %t", plan, custom), func(t *testing.T) {
				ctx := t.Context()
				id := fmt.Sprintf("%s-%t", plan, custom)
				u := h.as(t, id)
				h.seed(t, grant(c0.Scope(), "cluster.login", rbac.User, id))
				if custom {
					// On a cluster whose scope sorts before the others'.
					h.seed(t, grant(rbac.Scope{Type: "cluster", ID: "0"}, "custom.login", rbac.User, id))
				}
				granted := 0
				read := func(n int) int64 {
					t.Helper()
					if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
						SELECT 't1', 'cluster', 'other' || i, 'user', $3, 'cluster.login' FROM generate_series($1::int + 1, $2::int) i`, granted, n, id); err != nil {
						t.Fatal(err)
					}
					granted = n
					if _, err := h.pool.Exec(ctx, `ANALYZE rbac_grants`); err != nil {
						t.Fatal(err)
					}
					tx, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { _ = tx.Rollback(ctx) }()
					if _, err := tx.Exec(ctx, `SELECT set_config('plan_cache_mode', $1, true)`, plan); err != nil {
						t.Fatal(err)
					}
					start := pagesRead(ctx, t, tx, "rbac_grants")
					if _, err := h.authz.WithTx(tx).Filter(ctx, u, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1); err != nil {
						t.Fatal(err)
					}
					return pagesRead(ctx, t, tx, "rbac_grants") - start
				}
				if few, many := read(100), read(10000); many > few*3/2+deeper {
					t.Errorf("Filter read %d pages of grants for a subject holding 100 more on clusters, and %d for one holding 10000", few, many)
				}
			})
		}
	}
}

// Revoking a grant on a scope many hold grants on reads only the revoked principal's, under its
// lock, by Apply and by DeleteGrants, under a generic plan too: matched to the scope's grants, a
// revoke reads each of them.
func TestRevokingAGrantOnABusyScopeReadsOnlyItsPrincipals(t *testing.T) {
	for _, plan := range []string{"custom", "generic"} {
		t.Run(plan, func(t *testing.T) {
			var h *harness
			if plan == "generic" {
				h = generic(t)
			} else {
				h = setup(t)
			}
			ctx := t.Context()
			admin := h.as(t, "admin")
			ann := h.as(t, "ann")
			h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.admin", rbac.User, "admin"), grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "ann"))
			revoke := rbac.Binding{Role: "cluster.login", Principal: ann.Principal}
			read := func() map[string]int64 {
				t.Helper()
				pages := map[string]int64{}
				for what, f := range map[string]func(a *rbac.Authorizer) error{
					"Apply": func(a *rbac.Authorizer) error {
						return a.Apply(ctx, admin, tenantT1, rbac.Change{Revoke: []rbac.Binding{revoke}})
					},
					"DeleteGrants": func(a *rbac.Authorizer) error {
						return a.DeleteGrants(ctx, host, "t1", []rbac.Grant{{Scope: rbac.TenantRoot("t1"), Binding: revoke}})
					},
				} {
					tx, err := h.pool.Begin(ctx)
					if err != nil {
						t.Fatal(err)
					}
					start := pagesRead(ctx, t, tx, "rbac_grants")
					if err := f(h.authz.WithTx(tx)); err != nil {
						t.Fatalf("%s: %v", what, err)
					}
					var left bool
					if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT FROM rbac_grants WHERE principal = 'user:ann')`).Scan(&left); err != nil || left {
						t.Fatalf("%s left ann's grant: %v", what, err)
					}
					pages[what] = pagesRead(ctx, t, tx, "rbac_grants") - start
					_ = tx.Rollback(ctx)
				}
				return pages
			}
			others := func(n int) {
				t.Helper()
				manyMembers(t, h, n, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					SELECT 't1', 'tenant', 't1', 'user', id, 'cluster.login' FROM others`, "rbac_grants")
			}
			others(500)
			few := read()
			others(4500)
			for what, many := range read() {
				if many > few[what]*3/2+deeper {
					t.Errorf("%s read %d pages of grants, and %d once 4500 more held a role on the tenant", what, few[what], many)
				}
			}
		})
	}
}

// A change to a group's members reads, of the eligibilities and denies, only those of the groups
// it reaches, that they approve, and that name or exempt them, and of the places in groups only
// theirs, under a generic plan too: no btree seeks a key in an array, so it read every eligibility
// and deny in the tenant, and a generic plan, costing a read by the tenant as an average tenant's
// few rows, reads the eligibilities and places of a large tenant by it; and an index on the arrays
// alone would read those naming a group of the same id in every other tenant.
func TestChangingMembersReadsOnlyWhatTheGroupsReach(t *testing.T) {
	for _, plan := range []string{"custom", "generic"} {
		t.Run(plan, func(t *testing.T) {
			roles := func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), groupMembers, guardRole) }
			var h *harness
			if plan == "generic" {
				h = generic(t, roles)
			} else {
				h = custom(t, roles)
			}
			ctx := t.Context()
			h.groups(t, "oncall", "everyone", "pager")
			h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "manager"),
				grant(cluster.Scope(), "cluster.admin", rbac.User, "manager"), grant(cluster.Scope(), "guard", rbac.User, "manager"))
			manager := h.as(t, "manager")
			h.as(t, "ann", "oncall")
			h.as(t, "bob")
			// oncall is eligible on the cluster, approves v's activations there, and is named in one
			// deny there and exempt from another.
			for _, q := range []string{
				`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
				 VALUES ('t1', 'cluster', 'c1', 'group', 'oncall', 'cluster.sudo', 3600, '{}'),
				        ('t1', 'cluster', 'c1', 'user', 'v', 'cluster.sudo', 3600, '{group:oncall}')`,
				`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
				 VALUES ('t1', 'cluster', 'c1', 'named', '{group:oncall}', '{}', '{cluster:root}'),
				        ('t1', 'cluster', 'c1', 'exempt', '{user:v}', '{group:oncall}', '{cluster:root}')`,
			} {
				if _, err := h.pool.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			bob := []rbac.Member{{Group: "oncall", Principal: identity("bob")}}
			// The pages of the eligibilities, denies and places in groups, and their indexes, each
			// reads, in a transaction it rolls back.
			read := func() map[string]int64 {
				t.Helper()
				pages := map[string]int64{}
				for what, f := range map[string]func(a *rbac.Authorizer) error{
					"ImportMembers": func(a *rbac.Authorizer) error { return a.ImportMembers(ctx, host, "t1", bob) },
					"ImportMembers nesting a group": func(a *rbac.Authorizer) error {
						return a.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "oncall", Principal: groupOf("pager")}})
					},
					"ChangeMembers": func(a *rbac.Authorizer) error {
						return a.ChangeMembers(ctx, manager, "t1", bob, []rbac.Member{{Group: "oncall", Principal: identity("ann")}})
					},
					"ChangeMembers ending a place sooner": func(a *rbac.Authorizer) error {
						return a.ChangeMembers(ctx, manager, "t1", []rbac.Member{{Group: "oncall", Principal: identity("ann"), ExpiresAt: h.now.Add(time.Hour)}}, nil)
					},
				} {
					func() {
						tx, err := h.pool.Begin(ctx)
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = tx.Rollback(ctx) }()
						for _, table := range []string{"rbac_eligibilities", "rbac_denies", "rbac_members"} {
							pages[what+" of "+table] -= pagesRead(ctx, t, tx, table)
						}
						if err := f(h.authz.WithTx(tx)); err != nil {
							t.Fatalf("%s: %v", what, err)
						}
						for _, table := range []string{"rbac_eligibilities", "rbac_denies", "rbac_members"} {
							pages[what+" of "+table] += pagesRead(ctx, t, tx, table)
						}
					}()
				}
				return pages
			}
			// Others are in another group, and each has a group in a group of its own; each is eligible
			// on a cluster, which the other group approves, and named in a deny there it is exempt from;
			// and in a tenant each of their own, oncall approves an eligibility, and is named in a deny
			// and exempt from it.
			others := func(n int) {
				t.Helper()
				manyMembers(t, h, n, `, members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
					  SELECT 't1', 'everyone', 'user', id FROM others UNION ALL SELECT 't1', 'p' || id, 'group', 'g' || id FROM others),
					parents AS (INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'p' || id FROM others),
					eligible AS (INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
					  SELECT 't1', 'cluster', id, 'user', id, 'cluster.sudo', 3600, '{group:everyone}'::text[] FROM others
					  UNION ALL SELECT id, 'cluster', 'c1', 'user', id, 'cluster.sudo', 3600, '{group:oncall}' FROM others)
					INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
					SELECT 't1', 'cluster', id, 'd', ARRAY['user:' || id], '{group:everyone}'::text[], '{cluster:root}'::text[] FROM others
					UNION ALL SELECT id, 'cluster', 'c1', 'd', '{group:oncall}', '{group:oncall}', '{cluster:root}' FROM others`,
					"rbac_members", "rbac_eligibilities", "rbac_denies")
			}
			others(500)
			few := read()
			others(4500)
			for what, many := range read() {
				if many > few[what]*3/2+deeper {
					t.Errorf("%s read %d pages, and %d once 4500 more were eligible, denied and in groups, and named elsewhere", what, few[what], many)
				}
			}
		})
	}
}

// Without declared labels, a member leaving loses nothing a change checks but the denies naming its
// groups, so removing one, or ending its place sooner, reads nothing else of what they hold: as few
// pages however much the groups it is in hold.
func TestRemovingAMemberReadsNothingItsGroupsHold(t *testing.T) {
	h := grouped(t)
	ctx := t.Context()
	h.groups(t, "big", "inner")
	h.as(t, "ann", "inner")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'big', 'group', 'inner')`); err != nil {
		t.Fatal(err)
	}
	manager := h.as(t, "manager")
	tables := []string{"rbac_grants", "rbac_eligibilities"}
	from := 0
	// The pages of the grants and eligibilities each removal reads, in a transaction it rolls back,
	// once big holds n more of each on clusters, and approves n more activations.
	read := func(n int) map[string]int64 {
		t.Helper()
		for _, q := range []string{
			`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			 SELECT 't1', 'cluster', 'c' || i, 'group', 'big', 'cluster.login' FROM generate_series($1::int + 1, $1::int + $2::int) i`,
			`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
			 SELECT 't1', 'cluster', 'c' || i, 'group', 'big', 'cluster.sudo', 3600, '{}'::text[] FROM generate_series($1::int + 1, $1::int + $2::int) i
			 UNION ALL SELECT 't1', 'cluster', 'c' || i, 'user', 'v' || i, 'cluster.sudo', 3600, '{group:big}' FROM generate_series($1::int + 1, $1::int + $2::int) i`,
		} {
			if _, err := h.pool.Exec(ctx, q, from, n); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := h.pool.Exec(ctx, `ANALYZE rbac_grants, rbac_eligibilities`); err != nil {
			t.Fatal(err)
		}
		from += n
		pages := map[string]int64{}
		for what, change := range map[string][]rbac.Member{
			"removing ann":              nil,
			"ending ann's place sooner": {{Group: "inner", Principal: identity("ann"), ExpiresAt: h.now.Add(time.Hour)}},
		} {
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				for _, table := range tables {
					pages[what+" of "+table] -= pagesRead(ctx, t, tx, table)
				}
				var remove []rbac.Member
				if change == nil {
					remove = []rbac.Member{{Group: "inner", Principal: identity("ann")}}
				}
				if err := h.authz.WithTx(tx).ChangeMembers(ctx, manager, "t1", change, remove); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				for _, table := range tables {
					pages[what+" of "+table] += pagesRead(ctx, t, tx, table)
				}
			}()
		}
		return pages
	}
	few := read(500)
	for what, many := range read(9500) {
		if many > few[what]*3/2+deeper {
			t.Errorf("%s read %d pages, and %d once its groups held 9500 more grants and eligibilities", what, few[what], many)
		}
	}
}

// Of the grants, eligibilities and denies, a list by scope or by principal, a check's and Holders'
// read of the denies on a path, Activate's of the eligibilities, a write's count of a role's grants
// toward its bound, and DeleteScopes read only those of their scopes or principals, and Holders, of
// the places in groups, only those of the groups in a group granted, under a generic plan too: a
// generic plan costs scope = ANY(...) or principal = ANY(...) as ten seeks, and a read of the
// tenant by an index leading to it alone, which it costs as an average tenant's few rows, as
// cheaper, which reads every row of a large tenant.
func TestReadsByScopeOrPrincipalReadOnlyTheirRows(t *testing.T) {
	for _, plan := range []string{"custom", "generic"} {
		t.Run(plan, func(t *testing.T) {
			var h *harness
			if plan == "generic" {
				h = generic(t)
			} else {
				h = custom(t)
			}
			ctx := t.Context()
			h.groups(t, "oncall", "pager", "everyone")
			ann := h.as(t, "ann", "oncall")
			gone := []rbac.Scope{{Type: "cluster", ID: "c2"}, {Type: "cluster", ID: "c3"}}
			// ann holds a role on the cluster, as oncall, with pager in it, does there and on each scope
			// gone, where oncall is eligible and denied too, as it is eligible on the cluster, where a
			// deny names ann.
			for _, q := range []string{
				`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'oncall', 'group', 'pager')`,
				`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
				 VALUES ('t1', 'cluster', 'c1', 'user', 'ann', 'cluster.login'), ('t1', 'cluster', 'c1', 'group', 'oncall', 'cluster.login'),
				        ('t1', 'cluster', 'c2', 'group', 'oncall', 'cluster.login'), ('t1', 'cluster', 'c3', 'group', 'oncall', 'cluster.login')`,
				`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
				 VALUES ('t1', 'cluster', 'c1', 'group', 'oncall', 'cluster.sudo', 3600), ('t1', 'cluster', 'c2', 'group', 'oncall', 'cluster.sudo', 3600)`,
				`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
				 VALUES ('t1', 'cluster', 'c1', 'd', '{user:ann}', '{cluster:root}'), ('t1', 'cluster', 'c2', 'd', '{group:oncall}', '{cluster:root}')`,
			} {
				if _, err := h.pool.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			oncall := []rbac.Principal{groupOf("oncall")}
			tables := []string{"rbac_grants", "rbac_eligibilities", "rbac_denies", "rbac_members"}
			// The pages of the grants, eligibilities, denies and places in groups, and their indexes,
			// each reads, in a transaction it rolls back.
			read := func() map[string]int64 {
				t.Helper()
				pages := map[string]int64{}
				for what, f := range map[string]func(a *rbac.Authorizer) error{
					"Authorize": func(a *rbac.Authorizer) error { return a.Authorize(ctx, ann, login, cluster) },
					"Explain":   func(a *rbac.Authorizer) error { return second(a.Explain(ctx, ann, login, cluster)) },
					"Holders":   func(a *rbac.Authorizer) error { return second(a.Holders(ctx, login, cluster)) },
					"Grants by scope": func(a *rbac.Authorizer) error {
						return second(a.Grants(ctx, "t1", rbac.GrantFilter{Scopes: []rbac.Scope{cluster.Scope()}}))
					},
					"Eligibilities by scope": func(a *rbac.Authorizer) error {
						return second(a.Eligibilities(ctx, "t1", rbac.GrantFilter{Scopes: gone}))
					},
					"Eligibilities by principal": func(a *rbac.Authorizer) error {
						return second(a.Eligibilities(ctx, "t1", rbac.GrantFilter{Principals: oncall}))
					},
					"Denies": func(a *rbac.Authorizer) error { return second(a.Denies(ctx, "t1", gone)) },
					"Activate": func(a *rbac.Authorizer) error {
						return second(a.Activate(ctx, ann, cluster, rbac.Activation{Role: "cluster.sudo", Duration: time.Minute, Justification: "INC-1"}))
					},
					"DeleteScopes": func(a *rbac.Authorizer) error { return a.DeleteScopes(ctx, host, "t1", gone) },
				} {
					func() {
						tx, err := h.pool.Begin(ctx)
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = tx.Rollback(ctx) }()
						for _, table := range tables {
							pages[what+" of "+table] -= pagesRead(ctx, t, tx, table)
						}
						if err := f(h.authz.WithTx(tx)); err != nil {
							t.Fatalf("%s: %v", what, err)
						}
						for _, table := range tables {
							pages[what+" of "+table] += pagesRead(ctx, t, tx, table)
						}
					}()
				}
				return pages
			}
			// Others are in another group, and each has a group in a group of its own; each holds a
			// role on a cluster, is eligible there and on ann's cluster, and is denied on it.
			others := func(n int) {
				t.Helper()
				manyMembers(t, h, n, `, members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
					  SELECT 't1', 'everyone', 'user', id FROM others UNION ALL SELECT 't1', 'p' || id, 'group', 'g' || id FROM others),
					parents AS (INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'p' || id FROM others),
					granted AS (INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					  SELECT 't1', 'cluster', id, 'user', id, 'cluster.login' FROM others),
					eligible AS (INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds)
					  SELECT 't1', 'cluster', c, 'user', id, 'cluster.sudo', 3600 FROM others, unnest(ARRAY[id, 'c1']) AS c)
					INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
					SELECT 't1', 'cluster', id, 'd', ARRAY['user:' || id], '{cluster:root}'::text[] FROM others`,
					"rbac_grants", "rbac_eligibilities", "rbac_denies", "rbac_members")
			}
			others(500)
			few := read()
			others(4500)
			for what, many := range read() {
				if many > few[what]*3/2+deeper {
					t.Errorf("%s read %d pages, and %d once 4500 more were in groups, held a role, were eligible and were denied", what, few[what], many)
				}
			}
		})
	}
}

// DeleteScopes and DeletePrincipal read, of the grants, eligibilities, denies and places in groups,
// only those on their scopes or of their principal, under a generic plan too: each table's were
// matched to those it locked in order in a semi-join, which a generic plan, costing the tenant's
// rows as an average tenant's few, runs by reading every row of the tenant.
func TestDeletesReadOnlyTheirScopesOrPrincipalsRows(t *testing.T) {
	for _, plan := range []string{"custom", "generic"} {
		t.Run(plan, func(t *testing.T) {
			var h *harness
			if plan == "generic" {
				h = generic(t)
			} else {
				h = custom(t)
			}
			ctx := t.Context()
			h.groups(t, "oncall", "pager", "everyone")
			ann := h.as(t, "ann", "oncall")
			gone := []rbac.Scope{{Type: "cluster", ID: "c2"}, {Type: "cluster", ID: "c3"}}
			// ann and oncall, with pager in it, hold roles on the scopes gone, where oncall is eligible
			// and named in a deny ann is exempt from; the tenant's members and the public hold roles
			// there too.
			for _, q := range []string{
				`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'oncall', 'group', 'pager')`,
				`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
				 SELECT 't1', 'cluster', c, k, i, 'cluster.login' FROM unnest('{c2,c3}'::text[]) AS c,
				   unnest('{user,group,members,public}'::text[], '{ann,oncall,t1,""}'::text[]) AS p(k, i)`,
				`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
				 VALUES ('t1', 'cluster', 'c2', 'group', 'oncall', 'cluster.sudo', 3600, '{}'),
				        ('t1', 'cluster', 'c2', 'user', 'ann', 'cluster.sudo', 3600, '{group:oncall}')`,
				`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
				 VALUES ('t1', 'cluster', 'c2', 'd', '{group:oncall}', '{user:ann}', '{cluster:root}')`,
			} {
				if _, err := h.pool.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			tables := []string{"rbac_grants", "rbac_eligibilities", "rbac_denies", "rbac_members"}
			// The pages of the grants, eligibilities, denies and places in groups, and their indexes,
			// each reads, in a transaction it rolls back.
			read := func() map[string]int64 {
				t.Helper()
				pages := map[string]int64{}
				for what, f := range map[string]func(a *rbac.Authorizer) error{
					"DeleteScopes":                   func(a *rbac.Authorizer) error { return a.DeleteScopes(ctx, host, "t1", gone) },
					"DeletePrincipal of an identity": func(a *rbac.Authorizer) error { return a.DeletePrincipal(ctx, host, "t1", ann.Principal) },
					"DeletePrincipal of a group":     func(a *rbac.Authorizer) error { return a.DeletePrincipal(ctx, host, "t1", groupOf("oncall")) },
					"DeletePrincipal of the members": func(a *rbac.Authorizer) error { return a.DeletePrincipal(ctx, host, "t1", rbac.TenantMembers("t1")) },
					"DeletePrincipal of the public": func(a *rbac.Authorizer) error {
						return a.DeletePrincipal(ctx, host, "t1", rbac.Principal{Kind: rbac.Public})
					},
				} {
					func() {
						tx, err := h.pool.Begin(ctx)
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = tx.Rollback(ctx) }()
						for _, table := range tables {
							pages[what+" of "+table] -= pagesRead(ctx, t, tx, table)
						}
						if err := f(h.authz.WithTx(tx)); err != nil {
							t.Fatalf("%s: %v", what, err)
						}
						for _, table := range tables {
							pages[what+" of "+table] += pagesRead(ctx, t, tx, table)
						}
					}()
				}
				return pages
			}
			// Others are in another group, and each has a group in a group of its own; each holds a role
			// on the tenant and on a cluster of its own, where it is eligible and denied.
			others := func(n int) {
				t.Helper()
				manyMembers(t, h, n, `, members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
					  SELECT 't1', 'everyone', 'user', id FROM others UNION ALL SELECT 't1', 'p' || id, 'group', 'g' || id FROM others),
					parents AS (INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'p' || id FROM others),
					granted AS (INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
					  SELECT 't1', s, i, 'user', id, 'cluster.login' FROM others, unnest('{cluster,tenant}'::text[], ARRAY[id, 't1']) AS t(s, i)),
					eligible AS (INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
					  SELECT 't1', 'cluster', id, 'user', id, 'cluster.sudo', 3600, '{group:everyone}'::text[] FROM others)
					INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
					SELECT 't1', 'cluster', id, 'd', ARRAY['user:' || id], '{group:everyone}'::text[], '{cluster:root}'::text[] FROM others`,
					"rbac_grants", "rbac_eligibilities", "rbac_denies", "rbac_members", "rbac_groups")
			}
			others(500)
			few := read()
			others(4500)
			for what, many := range read() {
				if many > few[what]*3/2+deeper {
					t.Errorf("%s read %d pages, and %d once 4500 more were in groups, held roles, were eligible and were denied", what, few[what], many)
				}
			}
		})
	}
}

// Deleting a scope, or a group, with many denies on it reads about as many pages for each of them
// however many there are: each is locked by its primary key. By the index on the scope, each
// lookup reads every deny on the scope.
func TestDeletingAScopesDeniesReadsEachByItsKey(t *testing.T) {
	for _, plan := range []string{"custom", "generic"} {
		t.Run(plan, func(t *testing.T) {
			var h *harness
			if plan == "generic" {
				h = generic(t)
			} else {
				h = custom(t)
			}
			ctx := t.Context()
			h.groups(t, "g")
			denied := 0
			// The pages of the denies and their indexes each deletion reads once n denies are on the
			// cluster and on g, in a transaction it rolls back.
			read := func(n int) map[string]int64 {
				t.Helper()
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
					SELECT 't1', s, i, 'd' || j, '{public:}', '{cluster:login}' FROM (VALUES ('cluster', 'c1'), ('group', 'g')) v(s, i),
					  generate_series($1 + 1, $2) j`, denied, n); err != nil {
					t.Fatal(err)
				}
				denied = n
				if _, err := h.pool.Exec(ctx, `ANALYZE rbac_denies`); err != nil {
					t.Fatal(err)
				}
				pages := map[string]int64{}
				for what, f := range map[string]func(a *rbac.Authorizer) error{
					"DeleteScopes": func(a *rbac.Authorizer) error { return a.DeleteScopes(ctx, host, "t1", []rbac.Scope{cluster.Scope()}) },
					"DeleteGroups": func(a *rbac.Authorizer) error { return a.DeleteGroups(ctx, host, "t1", []string{"g"}) },
				} {
					func() {
						tx, err := h.pool.Begin(ctx)
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = tx.Rollback(ctx) }()
						start := pagesRead(ctx, t, tx, "rbac_denies")
						if err := f(h.authz.WithTx(tx)); err != nil {
							t.Fatalf("%s: %v", what, err)
						}
						pages[what] = pagesRead(ctx, t, tx, "rbac_denies") - start
					}()
				}
				return pages
			}
			few := read(100)
			for what, many := range read(1000) {
				if many > few[what]*10*3/2+deeper {
					t.Errorf("%s read %d pages with 100 denies on its scope, and %d with 1,000", what, few[what], many)
				}
			}
		})
	}
}

// Deleting groups reads, of the eligibilities and denies, only those of the groups, on them, that
// they approve, and that name or exempt them, under a generic plan too: found by those conditions
// ORed beside tenant = $1, which no index seeks, they were read from every eligibility and deny in
// the tenant.
func TestDeletingGroupsReadsOnlyWhatNamesThem(t *testing.T) {
	for _, plan := range []string{"custom", "generic"} {
		t.Run(plan, func(t *testing.T) {
			groups := rbac.RoleDefinition{ID: "tenant.groups", Permissions: []rbac.Permission{rbac.ManageGroups}, ResourceTypes: []string{rbac.TenantScope}}
			roles := func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), groups) }
			// On one connection, where a call made once beforehand has planned its statements: planning
			// one reads its indexes' metapages, as again once the tables are analyzed, which counts as
			// pages read.
			var h *harness
			if plan == "generic" {
				h = crowded(t, pgtest.Open(t, "plan_cache_mode=force_generic_plan&pool_max_conns=1"), roles)
			} else {
				h = setupOn(t, pgtest.Open(t, "plan_cache_mode=force_custom_plan&pool_max_conns=1"), roles)
			}
			ctx := t.Context()
			h.groups(t, "oncall", "pager", "spare", "everyone")
			h.seed(t, grant(rbac.TenantRoot("t1"), "tenant.groups", rbac.User, "admin"))
			admin := h.as(t, "admin")
			h.as(t, "ann", "oncall", "spare")
			// oncall holds a role on the cluster, and one is held on it; it is eligible on the cluster,
			// approves v's activations there, and is named in one deny there and exempt from another;
			// and a deny is set on it.
			for _, q := range []string{
				`INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'oncall', 'group', 'pager')`,
				`INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
				 VALUES ('t1', 'cluster', 'c1', 'group', 'oncall', 'cluster.login'), ('t1', 'group', 'oncall', 'user', 'admin', 'tenant.groups')`,
				`INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
				 VALUES ('t1', 'cluster', 'c1', 'group', 'oncall', 'cluster.sudo', 3600, '{}'),
				        ('t1', 'cluster', 'c1', 'user', 'v', 'cluster.sudo', 3600, '{group:oncall,user:admin}')`,
				`INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
				 VALUES ('t1', 'cluster', 'c1', 'named', '{group:oncall}', '{}', '{cluster:root}'),
				        ('t1', 'cluster', 'c1', 'exempt', '{user:v}', '{group:oncall}', '{cluster:root}'),
				        ('t1', 'group', 'oncall', 'on', '{user:v}', '{}', '{group:members}')`,
			} {
				if _, err := h.pool.Exec(ctx, q); err != nil {
					t.Fatal(err)
				}
			}
			tables := []string{"rbac_eligibilities", "rbac_denies"}
			// The pages of the eligibilities and denies, and their indexes, each reads, in a transaction it
			// rolls back.
			read := func() map[string]int64 {
				t.Helper()
				pages := map[string]int64{}
				for what, f := range map[string]func(a *rbac.Authorizer) error{
					"DeleteGroups": func(a *rbac.Authorizer) error { return a.DeleteGroups(ctx, host, "t1", []string{"oncall", "pager"}) },
					"DeleteGroup":  func(a *rbac.Authorizer) error { return a.DeleteGroup(ctx, admin, "t1", "spare") },
				} {
					for _, measured := range []bool{false, true} {
						func() {
							tx, err := h.pool.Begin(ctx)
							if err != nil {
								t.Fatal(err)
							}
							defer func() { _ = tx.Rollback(ctx) }()
							before := map[string]int64{}
							for _, table := range tables {
								before[table] = pagesRead(ctx, t, tx, table)
							}
							if err := f(h.authz.WithTx(tx)); err != nil {
								t.Fatalf("%s: %v", what, err)
							}
							for _, table := range tables {
								if measured {
									pages[what+" of "+table] = pagesRead(ctx, t, tx, table) - before[table]
								}
							}
						}()
					}
				}
				return pages
			}
			// Others are each eligible on a cluster of their own, which everyone approves, and named in a
			// deny there everyone is exempt from; and in a tenant each of their own, oncall approves an
			// eligibility, and is named in a deny and exempt from it.
			others := func(n int) {
				t.Helper()
				manyMembers(t, h, n, `, eligible AS (INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
					  SELECT 't1', 'cluster', id, 'user', id, 'cluster.sudo', 3600, '{group:everyone}'::text[] FROM others
					  UNION ALL SELECT id, 'cluster', 'c1', 'user', id, 'cluster.sudo', 3600, '{group:oncall}' FROM others)
					INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
					SELECT 't1', 'cluster', id, 'd', ARRAY['user:' || id], '{group:everyone}'::text[], '{cluster:root}'::text[] FROM others
					UNION ALL SELECT id, 'cluster', 'c1', 'd', '{group:oncall}', '{group:oncall}', '{cluster:root}' FROM others`,
					"rbac_eligibilities", "rbac_denies")
			}
			others(500)
			few := read()
			others(4500)
			for what, many := range read() {
				if many > few[what]*3/2+deeper {
					t.Errorf("%s read %d pages, and %d once 4500 more were eligible and denied, and oncall named elsewhere", what, few[what], many)
				}
			}
		})
	}
}

// Filter's condition and Reachable read, of the denies on the scopes a resource of the type can
// have on its path, only those binding the subject, under a generic plan too: by the scopes' type,
// they read every deny on resources of the type and on containers in the tenant, whoever it names,
// as its admins can put one on each of thousands; and by the keys binding the subject alone, every
// deny in the tenant naming the public or its members, on scopes of any type, as owners keeping
// groups to themselves set.
func TestListingsReadOnlyTheDeniesBindingTheirSubject(t *testing.T) {
	for _, plan := range []string{"custom", "generic"} {
		for shape, others := range map[string]string{
			// Others are each denied on a cluster or a workspace of their own.
			"named on the listed types": `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, permissions)
				SELECT 't1', CASE WHEN id < '8' THEN 'cluster' ELSE 'workspace' END, id, 'd', ARRAY['user:' || id], '{cluster:login}'::text[]
				FROM others`,
			// Others each deny everyone, the public or the tenant's members, all but themselves on a
			// group of their own.
			"everyone on another type": `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
				SELECT 't1', 'group', id, 'd', ARRAY[CASE WHEN id < '8' THEN 'public:' ELSE 'members:t1' END], ARRAY['user:' || id],
				  '{cluster:login}'::text[]
				FROM others`,
		} {
			t.Run(plan+", "+shape, func(t *testing.T) {
				var h *harness
				if plan == "generic" {
					h = generic(t)
				} else {
					h = crowded(t, pgtest.Open(t, "plan_cache_mode=force_custom_plan"))
				}
				ctx := t.Context()
				resources := hostTable(t, h)
				ann := h.as(t, "ann", "oncall")
				h.seed(t, grant(rbac.TenantRoot("t1"), "cluster.login", rbac.User, "ann"))
				// ann is denied on a cluster, oncall on a workspace and the public on another cluster;
				// the tenant's members are on another workspace, but ann is exempt there.
				if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
					VALUES ('t1', 'cluster', 'c0', 'd', '{user:ann}', '{}', '{cluster:login}'),
					       ('t1', 'workspace', 'w2', 'd', '{group:oncall}', '{}', '{cluster:*}'),
					       ('t1', 'cluster', 'c3', 'd', '{public:}', '{}', '{cluster:login}'),
					       ('t1', 'workspace', 'w3', 'd', '{members:t1}', '{user:ann}', '{cluster:login}')`); err != nil {
					t.Fatal(err)
				}
				// The pages of the denies and their indexes each reads, in a transaction it rolls back.
				read := func() map[string]int64 {
					t.Helper()
					pages := map[string]int64{}
					for what, f := range map[string]func(tx pgx.Tx, a *rbac.Authorizer) error{
						"Reachable": func(_ pgx.Tx, a *rbac.Authorizer) error {
							reach, err := a.Reachable(ctx, ann, login, "t1", "cluster")
							if err == nil && (!reach.All || len(reach.Except) != 3) {
								err = fmt.Errorf("reach %+v", reach)
							}
							return err
						},
						"Filter": func(tx pgx.Tx, a *rbac.Authorizer) error {
							pred, err := a.Filter(ctx, ann, login, "t1", "cluster", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
							if err != nil {
								return err
							}
							var kept int
							if err := tx.QueryRow(ctx, `SELECT count(*) FROM clusters WHERE `+pred.SQL, pred.Args...).Scan(&kept); err != nil {
								return err
							}
							if kept != len(resources)-3 {
								return fmt.Errorf("Filter kept %d of %d clusters", kept, len(resources))
							}
							return nil
						},
					} {
						func() {
							tx, err := h.pool.Begin(ctx)
							if err != nil {
								t.Fatal(err)
							}
							defer func() { _ = tx.Rollback(ctx) }()
							start := pagesRead(ctx, t, tx, "rbac_denies")
							if err := f(tx, h.authz.WithTx(tx)); err != nil {
								t.Fatalf("%s: %v", what, err)
							}
							pages[what] = pagesRead(ctx, t, tx, "rbac_denies") - start
						}()
					}
					return pages
				}
				manyMembers(t, h, 500, others, "rbac_denies")
				few := read()
				manyMembers(t, h, 4500, others, "rbac_denies")
				for what, many := range read() {
					if many > few[what]*3/2+deeper {
						t.Errorf("%s read %d pages of denies, and %d once 4500 more were denied", what, few[what], many)
					}
				}
			})
		}
	}
}

// A change naming groups, granting to one, a deny or an eligibility naming one, or members put in
// one, reads of the groups only those it names, under a generic plan too: tested for each whether
// it exists, flattened into an anti-join, which a generic plan, costing the tenant's groups as an
// average tenant's few, runs by reading every one.
func TestChangesNamingGroupsReadOnlyThoseGroups(t *testing.T) {
	for _, plan := range []string{"custom", "generic"} {
		t.Run(plan, func(t *testing.T) {
			roles := func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), groupMembers, guardRole) }
			var h *harness
			if plan == "generic" {
				h = generic(t, roles)
			} else {
				h = custom(t, roles)
			}
			ctx := t.Context()
			h.groups(t, "oncall", "pager")
			h.seed(t, grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "owner"), grant(cluster.Scope(), "guard", rbac.User, "owner"))
			owner := h.as(t, "owner")
			ann := h.as(t, "ann")
			oncall, pager := groupOf("oncall"), groupOf("pager")
			// The pages of the groups each reads, in a transaction it rolls back.
			read := func() map[string]int64 {
				t.Helper()
				pages := map[string]int64{}
				for what, f := range map[string]func(a *rbac.Authorizer) error{
					"Apply": func(a *rbac.Authorizer) error {
						return a.Apply(ctx, owner, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: oncall}}})
					},
					"Import": func(a *rbac.Authorizer) error {
						return a.Import(ctx, host, "t1", []rbac.Grant{grant(cluster.Scope(), "cluster.login", rbac.Group, "oncall")})
					},
					"SetDeny": func(a *rbac.Authorizer) error {
						return a.SetDeny(ctx, owner, cluster, rbac.Deny{ID: "d", Principals: []rbac.Principal{oncall}, Exempt: []rbac.Principal{pager}, Permissions: []rbac.Permission{root}})
					},
					"SetEligibility": func(a *rbac.Authorizer) error {
						return a.SetEligibility(ctx, owner, cluster, rbac.Eligibility{Role: "cluster.login", Principal: oncall, MaxDuration: time.Hour, Approvers: []rbac.Principal{pager}})
					},
					"ImportMembers": func(a *rbac.Authorizer) error {
						return a.ImportMembers(ctx, host, "t1", []rbac.Member{{Group: "oncall", Principal: ann.Principal}, {Group: "oncall", Principal: pager}})
					},
					"ChangeMembers": func(a *rbac.Authorizer) error {
						return a.ChangeMembers(ctx, owner, "t1", []rbac.Member{{Group: "oncall", Principal: ann.Principal}}, nil)
					},
				} {
					func() {
						tx, err := h.pool.Begin(ctx)
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = tx.Rollback(ctx) }()
						start := pagesRead(ctx, t, tx, "rbac_groups")
						if err := f(h.authz.WithTx(tx)); err != nil {
							t.Fatalf("%s: %v", what, err)
						}
						pages[what] = pagesRead(ctx, t, tx, "rbac_groups") - start
					}()
				}
				return pages
			}
			// Others each have a group of their own.
			others := func(n int) {
				t.Helper()
				manyMembers(t, h, n, `INSERT INTO rbac_groups (tenant, id) SELECT 't1', 'g' || id FROM others`, "rbac_groups")
			}
			others(500)
			few := read()
			others(4500)
			for what, many := range read() {
				if many > few[what]*3/2+deeper {
					t.Errorf("%s read %d pages of groups, and %d once 4500 more had a group of their own", what, few[what], many)
				}
			}
		})
	}
}

// Under PostgreSQL's default plan_cache_mode, a connection's statement may turn generic from its
// sixth run, and a change by an actor in a nested group, GroupsOf, and a change to a group's members
// read on each later call about as many pages as on the first, as they do under a generic plan.
func TestReadsStayBoundedOnceAConnectionsStatementsTurnGeneric(t *testing.T) {
	h := crowded(t, pgtest.Open(t, "pool_max_conns=1"), func(c *rbac.Config) { c.Catalog = append(slices.Clone(c.Catalog), groupMembers) })
	ctx := t.Context()
	h.groups(t, "builders", "oncall", "everyone")
	if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id) VALUES ('t1', 'builders', 'group', 'inner')`); err != nil {
		t.Fatal(err)
	}
	boss := h.as(t, "boss", "inner")
	ann := h.as(t, "ann", "oncall")
	h.as(t, "bob")
	h.seed(t, grant(cluster.Scope(), "cluster.admin", rbac.User, "boss"), grant(cluster.Scope(), "cluster.login", rbac.Group, "builders"),
		grant(cluster.Scope(), "cluster.login", rbac.Group, "oncall"), grant(rbac.TenantRoot("t1"), "group.members", rbac.User, "boss"))
	manyMembers(t, h, 5000, `, members AS (INSERT INTO rbac_members (tenant, group_id, principal_kind, principal_id)
		  SELECT 't1', 'everyone', 'user', id FROM others),
		eligible AS (INSERT INTO rbac_eligibilities (tenant, scope_type, scope_id, principal_kind, principal_id, role, max_seconds, approvers)
		  SELECT 't1', 'cluster', id, 'user', id, 'cluster.sudo', 3600, '{group:everyone}'::text[] FROM others)
		INSERT INTO rbac_denies (tenant, scope_type, scope_id, id, principals, exempt, permissions)
		SELECT 't1', 'cluster', id, 'd', ARRAY['user:' || id], '{group:everyone}'::text[], '{cluster:root}'::text[] FROM others`,
		"rbac_grants", "rbac_members", "rbac_eligibilities", "rbac_denies")
	tables := []string{"rbac_grants", "rbac_eligibilities", "rbac_denies", "rbac_members"}
	for what, f := range map[string]func(a *rbac.Authorizer) error{
		"Apply in a nested group": func(a *rbac.Authorizer) error {
			return a.Apply(ctx, boss, cluster, rbac.Change{Grant: []rbac.Binding{{Role: "cluster.login", Principal: ann.Principal}}})
		},
		"GroupsOf": func(a *rbac.Authorizer) error { return second(a.GroupsOf(ctx, "t1", boss.Principal)) },
		"ChangeMembers": func(a *rbac.Authorizer) error {
			return a.ChangeMembers(ctx, boss, "t1", []rbac.Member{{Group: "oncall", Principal: identity("bob")}}, []rbac.Member{{Group: "oncall", Principal: ann.Principal}})
		},
	} {
		// The pages of each table, and its indexes, each call reads, in a transaction it rolls back,
		// on the pool's one connection.
		var first map[string]int64
		for call := range 8 {
			pages := map[string]int64{}
			func() {
				tx, err := h.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = tx.Rollback(ctx) }()
				for _, table := range tables {
					pages[table] -= pagesRead(ctx, t, tx, table)
				}
				if err := f(h.authz.WithTx(tx)); err != nil {
					t.Fatalf("%s: %v", what, err)
				}
				for _, table := range tables {
					pages[table] += pagesRead(ctx, t, tx, table)
				}
			}()
			if first == nil {
				first = pages
			}
			for _, table := range tables {
				if pages[table] > first[table]*3/2+deeper {
					t.Errorf("%s read %d pages of %s on its first call, and %d on call %d", what, first[table], table, pages[table], call+1)
				}
			}
		}
	}
}

// statementsKept is a transaction that keeps the statements Query and QueryRow run on it, with
// their arguments.
type statementsKept struct {
	pgx.Tx
	statements []statement
}

type statement struct {
	sql  string
	args []any
}

func (r *statementsKept) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	r.statements = append(r.statements, statement{sql, args})
	return r.Tx.Query(ctx, sql, args...)
}

func (r *statementsKept) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	r.statements = append(r.statements, statement{sql, args})
	return r.Tx.QueryRow(ctx, sql, args...)
}

// planRows is how many rows the plans of statements pass, with those their filters remove, each
// run again under EXPLAIN ANALYZE on tx.
func planRows(ctx context.Context, t *testing.T, tx pgx.Tx, statements []statement) float64 {
	t.Helper()
	type node struct {
		Rows       float64 `json:"Actual Rows"`
		Filtered   float64 `json:"Rows Removed by Filter"`
		JoinFilter float64 `json:"Rows Removed by Join Filter"`
		Loops      float64 `json:"Actual Loops"`
		Plans      []node
	}
	var rows func(node) float64
	rows = func(p node) float64 {
		sum := (p.Rows + p.Filtered + p.JoinFilter) * p.Loops
		for _, c := range p.Plans {
			sum += rows(c)
		}
		return sum
	}
	var sum float64
	for _, s := range statements {
		var plan []struct{ Plan node }
		if err := tx.QueryRow(ctx, `EXPLAIN (ANALYZE, FORMAT JSON) `+s.sql, s.args...).Scan(&plan); err != nil {
			t.Fatalf("%v: %s", err, s.sql)
		}
		sum += rows(plan[0].Plan)
	}
	return sum
}

// Searches decide which custom roles granted to the public or the tenant's members give through
// them without pairing each one's permissions and types with the catalog's in their statements, so
// the rows those pass don't grow with the roles' permissions and types.
func TestSearchesDecideCustomRolesGrantedToBroadPrincipalsWithoutPairingTheirPermissions(t *testing.T) {
	rowsOf := func(t *testing.T, types, verbs int) float64 {
		t.Helper()
		var ts []string
		var perms []rbac.Permission
		for i := range types {
			ty := fmt.Sprintf("t%02d", i)
			ts = append(ts, ty)
			for v := range verbs {
				perms = append(perms, rbac.Permission(fmt.Sprintf("%s:v%02d", ty, v)))
			}
		}
		viewer := rbac.RoleDefinition{ID: "viewer", Permissions: perms, ResourceTypes: ts}
		admin := rbac.RoleDefinition{ID: "admin", Permissions: []rbac.Permission{rbac.GrantPermission(rbac.TenantScope)}, ResourceTypes: []string{rbac.TenantScope}}
		h := setup(t, func(c *rbac.Config) {
			c.Catalog = []rbac.RoleDefinition{viewer, admin}
			c.ContainerTypes = []string{"org"}
		})
		ctx := t.Context()
		ann := h.as(t, "ann")
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_roles (tenant, id, permissions, resource_types, public)
			SELECT 't1', 'custom.r' || i, $1::text[], $2::text[], i = 1 FROM generate_series(1, 5) i`, perms, ts); err != nil {
			t.Fatal(err)
		}
		if _, err := h.pool.Exec(ctx, `INSERT INTO rbac_grants (tenant, scope_type, scope_id, principal_kind, principal_id, role)
			VALUES ('t1', 'tenant', 't1', 'public', '', 'custom.r1'), ('t1', 'tenant', 't1', 'members', 't1', 'custom.r2')`); err != nil {
			t.Fatal(err)
		}
		if _, err := h.pool.Exec(ctx, `CREATE TABLE things (tenant text NOT NULL, id text NOT NULL, path text[] NOT NULL);
			INSERT INTO things SELECT 't1', 'x' || i, ARRAY['t00:x' || i, 'tenant:t1'] FROM generate_series(1, 10) i`); err != nil {
			t.Fatal(err)
		}
		tx, err := h.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		rec := &statementsKept{Tx: tx}
		a := h.authz.WithTx(rec)
		p, r := perms[0], rbac.Resource{Tenant: "t1", Type: "t00", ID: "x1"}
		holders, err := a.Holders(ctx, p, r)
		if err != nil || len(holders) != 2 {
			t.Fatalf("Holders = %+v, %v", holders, err)
		}
		if reach, err := a.Reachable(ctx, ann, p, "t1", "t00"); err != nil || !reach.All {
			t.Fatalf("Reachable = %+v, %v", reach, err)
		}
		pred, err := a.Filter(ctx, ann, p, "t1", "t00", rbac.Columns{Tenant: "tenant", Path: "path"}, 1)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := rec.Query(ctx, `SELECT id FROM things WHERE `+pred.SQL, pred.Args...)
		if err != nil {
			t.Fatal(err)
		}
		if ids, err := pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || len(ids) != 10 {
			t.Fatalf("Filter kept %v: %v", ids, err)
		}
		return planRows(ctx, t, tx, rec.statements)
	}
	small, large := rowsOf(t, 1, 1), rowsOf(t, 20, 10)
	if large > 2*small {
		t.Errorf("searches passed %.0f rows with custom roles of one permission on one type, and %.0f with roles of 200 on 20", small, large)
	}
}
