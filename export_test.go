package rbac

import (
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"github.com/jackc/pgx/v5"
)

// SetSavepointEnd bounds a savepoint's release or rollback by d until t ends.
func SetSavepointEnd(t *testing.T, d time.Duration) {
	t.Helper()
	old := savepointEnd
	savepointEnd = d
	t.Cleanup(func() { savepointEnd = old })
}

// SetMaxPrune bounds what one PruneHistory deletes to n until t ends.
func SetMaxPrune(t *testing.T, n int) {
	t.Helper()
	old := maxPrune
	maxPrune = n
	t.Cleanup(func() { maxPrune = old })
}

// SetPrunedWindow runs f at the end of each of PruneHistory's transactions, on it, until t ends.
func SetPrunedWindow(t *testing.T, f func(pgx.Tx)) {
	t.Helper()
	old := prunedWindow
	prunedWindow = f
	t.Cleanup(func() { prunedWindow = old })
}

// SetMaxHistoryBytes bounds the bytes one History call reads to n until t ends.
func SetMaxHistoryBytes(t *testing.T, n int) {
	t.Helper()
	old := maxHistoryBytes
	maxHistoryBytes = n
	t.Cleanup(func() { maxHistoryBytes = old })
}

// SetMaxUnsized bounds the records one History call measures that no trigger counted to n until t
// ends.
func SetMaxUnsized(t *testing.T, n int) {
	t.Helper()
	old := maxUnsized
	maxUnsized = n
	t.Cleanup(func() { maxUnsized = old })
}

// SetExpiryBatch bounds what one of DeleteExpired's transactions deletes from a table to n until t
// ends.
func SetExpiryBatch(t *testing.T, n int) {
	t.Helper()
	old := expiryBatch
	expiryBatch = n
	t.Cleanup(func() { expiryBatch = old })
}

// SetMaxContainerOverlap makes Filter look up the grants on containers and the tenant of a subject
// that holds more than n of them, rather than overlap them with each row's path, until t ends.
func SetMaxContainerOverlap(t *testing.T, n int) {
	t.Helper()
	old := maxContainerOverlap
	maxContainerOverlap = n
	t.Cleanup(func() { maxContainerOverlap = old })
}

// SetReadingRoles runs f once a read has read grants and the custom roles with them, until t
// ends.
func SetReadingRoles(t *testing.T, f func()) {
	t.Helper()
	old := readingRoles
	readingRoles = f
	t.Cleanup(func() { readingRoles = old })
}

// SetCheckingRole runs f each time a decision begins checking a role for a grant, until t ends.
func SetCheckingRole(t *testing.T, f func()) {
	t.Helper()
	old := checkingRole
	checkingRole = f
	t.Cleanup(func() { checkingRole = old })
}

// SetCheckingCondition runs f each time a change begins checking a condition it hasn't, until t
// ends.
func SetCheckingCondition(t *testing.T, f func()) {
	t.Helper()
	old := checkingCondition
	checkingCondition = f
	t.Cleanup(func() { checkingCondition = old })
}

// SetParsingCondition runs f each time a change begins parsing a condition for whether it reads
// the subject, until t ends.
func SetParsingCondition(t *testing.T, f func()) {
	t.Helper()
	old := parsingCondition
	parsingCondition = f
	t.Cleanup(func() { parsingCondition = old })
}

// SetDecidingGrants runs f as a change begins deciding its grants, and what f returns once it has,
// until t ends.
func SetDecidingGrants(t *testing.T, f func() func()) {
	t.Helper()
	old := decidingGrants
	decidingGrants = f
	t.Cleanup(func() { decidingGrants = old })
}

// StandSQL is the statement a change reads the standing of its principals with.
var StandSQL = standSQL

// HoldSQL is the statement Activate holds the places it rests on and reads its subject's paths
// with: tenant $1, the identity's key $2, now $3, until $4.
var HoldSQL = holdSQL

// RestsSQL is the statement a change ending places reads the paths left to activations with:
// tenant $1, the activations' ids $2, now $3.
var RestsSQL = restsSQL

// DeepCopy is the copy of attributes each hook is given.
func DeepCopy(attributes map[string]any) map[string]any { return deepCopy(attributes) }

// Compiled is how many conditions a keeps compiled for checks.
func Compiled(a *Authorizer) int {
	a.conds.mu.RLock()
	defer a.conds.mu.RUnlock()
	return len(a.conds.programs)
}

// Limits is how many conditions a keeps the limit of, the most evaluating each can cost.
func Limits(a *Authorizer) int {
	a.conds.mu.RLock()
	defer a.conds.mu.RUnlock()
	return len(a.conds.limits)
}

// CountEvaluations counts the conditions evaluated until t ends.
func CountEvaluations(t *testing.T) *int {
	t.Helper()
	old, n := evaluating, new(int)
	evaluating = func() { *n++ }
	t.Cleanup(func() { evaluating = old })
	return n
}

// ConditionCost is the most evaluating expr can cost, which a check runs it within, and what
// evaluating it on a request with attributes, which the resource carries too, costs, up to
// maxCost, built with the package's CEL environment extended by opts.
func ConditionCost(t *testing.T, expr string, attributes map[string]any, opts ...cel.EnvOption) (limit, actual uint64) {
	t.Helper()
	return ConditionCostOn(t, expr, Subject{Principal: Principal{Kind: User, ID: "u"}}, "cluster:login",
		Resource{Tenant: "t", Type: "cluster", ID: "c", Attributes: attributes}, attributes, opts...)
}

// MaxPermission is the longest action conditions are bounded for.
const MaxPermission = maxPermission

// ConditionCostOn is ConditionCost for s asking to do p to r, on a request with attributes.
func ConditionCostOn(t *testing.T, expr string, s Subject, p Permission, r Resource, attributes map[string]any, opts ...cel.EnvOption) (limit, actual uint64) {
	t.Helper()
	c, err := newConditions(Attributes{})
	if err != nil {
		t.Fatal(err)
	}
	if len(opts) > 0 {
		if c.env, err = c.env.Extend(opts...); err != nil {
			t.Fatal(err)
		}
	}
	prg, err := c.build(expr)
	if err != nil {
		t.Fatal(err)
	}
	checked, iss := c.env.Compile(expr)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}
	patterns, err := checkPatterns(checked)
	if err != nil {
		t.Fatal(err)
	}
	unlimited, err := c.env.Program(checked, cel.CostLimit(maxCost), cel.CostTracking(costs{patterns}),
		cel.OptimizeRegex(matching(patterns)), cel.CustomDecorator(bounded))
	if err != nil {
		t.Fatal(err)
	}
	a := &Authorizer{cfg: Config{Now: time.Now}, conds: c}
	vars := a.vars(WithRequest(t.Context(), attributes), s, p, r)
	_, details, _ := unlimited.Eval(vars)
	return prg.limit, *details.ActualCost()
}

// SetHoldingPlaces runs f as Activate begins holding the places in groups it can rest on, and what
// f returns once it holds them, until t ends.
func SetHoldingPlaces(t *testing.T, f func() func()) {
	t.Helper()
	old := holdingPlaces
	holdingPlaces = f
	t.Cleanup(func() { holdingPlaces = old })
}
