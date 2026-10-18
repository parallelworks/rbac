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
