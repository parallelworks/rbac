package rbac

import (
	"testing"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/interpreter"
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

// SetReadingKeys runs f once an activation has read its approver's keys, until t ends.
func SetReadingKeys(t *testing.T, f func()) {
	t.Helper()
	old := readingKeys
	readingKeys = f
	t.Cleanup(func() { readingKeys = old })
}

// SetCheckingRole runs f each time a decision begins checking a role for a grant, until t ends.
func SetCheckingRole(t *testing.T, f func()) {
	t.Helper()
	old := checkingRole
	checkingRole = f
	t.Cleanup(func() { checkingRole = old })
}

// SetReadingEntries runs f each time a decision reads n entries of a role's permissions and types, or of
// what the constraints answered, until t ends.
func SetReadingEntries(t *testing.T, f func(n int)) {
	t.Helper()
	old := readingEntries
	readingEntries = f
	t.Cleanup(func() { readingEntries = old })
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

// EndsSQL is the statement a change reads when its actor's paths to each key it holds end with:
// tenant $1, the identity's key $2, now $3.
var EndsSQL = `WITH RECURSIVE ` + endsSQL("$2::text", "$3") + ` SELECT k, e FROM ends`

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
	checked, patterns := compiled(t, c, expr)
	unlimited, err := plan(c.env, checked, patterns, maxCost)
	if err != nil {
		t.Fatal(err)
	}
	a := &Authorizer{cfg: Config{Now: time.Now}, conds: c}
	vars := a.vars(WithRequest(t.Context(), attributes), s, p, r)
	return prg.limit, evaluate(program{Program: unlimited, limit: maxCost}, vars).cost
}

// compiled is expr as c compiles it, and the sizes of its patterns.
func compiled(t *testing.T, c *conditions, expr string) (*cel.Ast, map[string]uint64) {
	t.Helper()
	checked, iss := c.env.Compile(expr)
	if iss.Err() != nil {
		t.Fatal(iss.Err())
	}
	patterns, err := checkPatterns(checked)
	if err != nil {
		t.Fatal(err)
	}
	return checked, patterns
}

// TrackedValues is what evaluating expr costs, on a request with attributes, which the resource
// carries too, as declares declares them, and how many values CEL's cost tracking holds at most as
// the evaluation reaches a uint literal, and how many times it does.
func TrackedValues(t *testing.T, declares Attributes, expr string, attributes map[string]any) (cost uint64, most, reached int) {
	t.Helper()
	c, err := newConditions(declares)
	if err != nil {
		t.Fatal(err)
	}
	checked, patterns := compiled(t, c, expr)
	limit := worstCost(checked, patterns)
	p := &probing{}
	prg, err := plan(c.env, checked, patterns, limit, cel.CustomDecoratorV2(p.decorate))
	if err != nil {
		t.Fatal(err)
	}
	a := &Authorizer{cfg: Config{Now: time.Now, Attributes: declares}, conds: c}
	vars := a.vars(WithRequest(t.Context(), attributes), Subject{Principal: Principal{Kind: User, ID: "u"}}, "cluster:login",
		Resource{Tenant: "t", Type: "cluster", ID: "c", Attributes: attributes})
	return evaluate(program{Program: prg, limit: limit}, vars).cost, p.most, p.reached
}

// PlanLoopsOtherwise is why expr can't be planned as a condition where CEL plans each of its loops'
// conditions as replan makes it, as another version of CEL may, or nil.
func PlanLoopsOtherwise(t *testing.T, expr string, replan func(interpreter.InterpretableV2) interpreter.InterpretableV2) error {
	t.Helper()
	c, err := newConditions(Attributes{})
	if err != nil {
		t.Fatal(err)
	}
	checked, patterns := compiled(t, c, expr)
	conds := newStepping(checked.NativeRep(), maxCost).ranges
	_, err = plan(c.env, checked, patterns, maxCost, cel.CustomDecoratorV2(func(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
		if _, ok := conds[i.ID()]; ok {
			return replan(i), nil
		}
		return i, nil
	}))
	return err
}

// probing plans each uint literal as a probe, which evaluates and is charged as the literal, but
// which CEL's cost tracking reads as a call of an argument none of the values it holds is of, so
// it reads them all.
type probing struct{ read, most, reached int }

func (p *probing) decorate(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
	if c, ok := i.(interpreter.InterpretableConst); ok {
		if _, isUint := c.Value().(types.Uint); isUint {
			return &probe{InterpretableV2: i, p: p}, nil
		}
	}
	return i, nil
}

type probe struct {
	interpreter.InterpretableV2
	p *probing
}

func (*probe) Function() string   { return "@probe" }
func (*probe) OverloadID() string { return "" }
func (r *probe) Args() []interpreter.InterpretableV2 {
	return []interpreter.InterpretableV2{unheld{r.p}}
}

func (r *probe) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	r.p.read = 0
	r.p.reached++
	return r.InterpretableV2.Exec(frame)
}

// unheld counts each value the tracking reads in search of it.
type unheld struct{ p *probing }

func (u unheld) ID() int64 {
	u.p.read++
	u.p.most = max(u.p.most, u.p.read)
	return -1
}

func (unheld) Eval(interpreter.Activation) ref.Val      { return types.NullValue }
func (unheld) Exec(*interpreter.ExecutionFrame) ref.Val { return types.NullValue }

// SetHoldingPlaces runs f as Activate begins holding the places in groups it can rest on, and what
// f returns once it holds them, until t ends.
func SetHoldingPlaces(t *testing.T, f func() func()) {
	t.Helper()
	old := holdingPlaces
	holdingPlaces = f
	t.Cleanup(func() { holdingPlaces = old })
}
