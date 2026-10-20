package rbac

import (
	"testing"
	"time"
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

// DeepCopy is the copy of attributes each hook is given.
func DeepCopy(attributes map[string]any) map[string]any { return deepCopy(attributes) }

// Compiled is how many conditions a keeps compiled for checks.
func Compiled(a *Authorizer) int {
	a.conds.mu.RLock()
	defer a.conds.mu.RUnlock()
	return len(a.conds.programs)
}
