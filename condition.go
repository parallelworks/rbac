package rbac

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/operators"
	"cel.dev/cel-go/common/overloads"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
	"cel.dev/cel-go/interpreter"
)

// Condition limits a grant to the requests its expression allows, in the Common Expression
// Language (CEL). It reads:
//
//	subject.kind, subject.id, subject.attributes             // Subject.Attributes
//	resource.type, resource.id, resource.tenant, resource.attributes // Resource.Attributes
//	request.time, request.attributes                          // WithRequest
//	action                                                    // the permission asked for
//
// such as `request.time < timestamp("2027-01-01T00:00:00Z") && resource.attributes.env != "prod"`.
// A grant with one gives its role only where the expression is true. An expression that fails,
// as one reading an attribute the host didn't pass does, or comparing a double that isn't finite,
// as dividing by zero makes, is false. The zero Condition is none,
// and one with a title or description has an expression. A pattern it matches is a string
// literal, of bounded size; it nests at most 32 deep; and a comparison, or a search of a list, that
// would read more than a condition may spend fails before it runs.
//
// What a check may spend on conditions is bounded, for each scope on its path, and so are the
// conditions stored, so that a check evaluates whole every one it reads: those of an identity's
// grants on a scope cost at most so much together, and those of a scope's grants to groups, the
// tenant's members and the public, which reach many, as much again, those from each source the
// host owns (Config.Sources) apart from the rest; those of a scope's denies (SetDeny); and the
// requirements of the eligibilities of groups for a role on a scope. Each distinct condition
// counts once, as what compiling it and evaluating it to its bound cost: about seven short ones,
// or three of the longest. A check of a labeled resource decides each of the subject's label
// values as a check of it would, and evaluates a condition that doesn't read the action once for
// them all, so on the tenant one that does counts once for each label value its grants give or its
// denies deny. A change adding a condition past a bound, or one evaluated more, is refused as
// invalid, so no grant, deny or eligibility stored changes what the others decide, but one adding
// none isn't: conditions stored past a bound before there were bounds can be stored again as they
// are, as by a restore. A check may not reach all of those, or of those of a custom role widened
// since: it evaluates the cheapest first, and past its budget a grant's condition is false and a
// deny's applies.
//
// Searches (Filter, Reachable, Holders) can't evaluate one: Filter and Reachable count only
// unconditional grants, Filter counts a conditional deny as denying, and Reach.Conditional and
// Reach.ConditionalExcept name the scopes conditional grants may reach and conditional denies
// cover, whose resources a host checks one by one. Holders lists those who hold only under a
// condition, or whom a conditional deny may bind, and marks them (Holder.Conditional,
// Holder.MaybeDenied).
type Condition struct {
	Title       string
	Description string
	Expression  string
}

// maxCost and maxPattern bound a condition, so one can't make checks slow. maxPattern bounds its
// patterns together, by about how many instructions they compile to: a program compiles them when
// it is built, which no cost counts, and a short pattern can compile to a large program.
const (
	maxCost    = 10000
	maxPattern = 1000
	// maxCached bounds the programs kept by the length of their expressions: a program is up to
	// about a hundred times its expression's length, so a count alone would let long conditions
	// hold gigabytes.
	maxCached = 256 << 10
	// zoneCost is what reading a time in a named zone costs: it loads the zone each time.
	zoneCost = 100
	// maxCheckCost is what the conditions a check reads cost together where they are bounded: an
	// identity's grants on a scope, a scope's grants that reach many, each the tenant's and from
	// each source the host owns, its denies, and the requirements of groups' eligibilities for a
	// role on it. A check, and a listing or a change for each permission it decides, may spend that
	// much on each for each scope of its path, so many conditional grants can't make it slow, and
	// evaluates them whole.
	maxCheckCost = 8 * maxCost
	// compilePerByte is what compiling a condition costs for each byte of it. Compiling one takes
	// about as long as evaluating forty units of cost for each, twice that where attributes are
	// declared, as it is checked against them too, but once for each condition, which checks then
	// read from the cache, so this counts it cheaper: a check of conditions none of which is cached
	// can take a few times what its budget implies.
	compilePerByte = 8
	// maxDepth bounds how deeply a condition nests: checking its types takes time that grows much
	// faster than its length with depth, which compilePerByte doesn't count.
	maxDepth = 32
)

// budget is what is left for a check to spend on conditions, the conditions it has paid to
// compile, and what those it evaluated decided, for each action: one condition decides the same
// for a request, so a check pays to evaluate it once however many grants or denies have it.
type budget struct {
	left uint64
	// exhausted is set once a condition couldn't be paid for: left reaching 0 doesn't say so, as
	// one evaluated can spend exactly what was left.
	exhausted bool
	compiled  map[string]bool
	decided   map[string]decision
	// ran is what conditions came to, evaluated on the same request but for its action, which a
	// listing's budgets for each permission share: each pays for a condition as if it evaluated it,
	// so it decides as a check of its permission would, but one that doesn't read the action runs
	// once for them all. nil for a budget that shares none, whose one request decided covers.
	ran map[string]run
}

// decision is what evaluating a condition decided.
type decision struct{ held, evaluated bool }

// run is what evaluating a condition came to, and what it cost.
type run struct {
	held, evaluated bool
	cost            uint64
}

// sharing is b, which shares what conditions came to with the budgets of others, ran, on the same
// request but for its action.
func (b *budget) sharing(ran map[string]run) *budget {
	b.ran = ran
	return b
}

// grantBudget is a check's budget for its grants' conditions on a path of scopes: the subject's own
// on a scope and those of the scope's grants that reach many each cost at most maxCheckCost, the
// tenant's and those from each source the host owns apart (conditionBucket), so a check may spend
// that for each of them on each scope of its path, and evaluates them whole however many grants or
// groups it reads, or a third party adds.
func (a *Authorizer) grantBudget(path []string) *budget {
	return budgetOf(uint64(len(path)) * 2 * uint64(1+len(a.owned)) * maxCheckCost)
}

// newDenyBudget is a check's budget for the denies' conditions on a path of scopes, apart from
// what it spends on its grants', so neither leaves the other nothing: a scope's conditional denies
// cost at most maxCheckCost together (SetDeny), so a check may spend that much for each scope of
// its path, and evaluates them whole however deep it is.
func newDenyBudget(path []string) *budget { return budgetOf(uint64(len(path)) * maxCheckCost) }

func budgetOf(left uint64) *budget {
	return &budget{left: left, compiled: map[string]bool{}, decided: map[string]decision{}}
}

// most is what a check can spend on conditions: each compiled once, and evaluated to its bound as
// many times as evaluations has it, and at least once.
func most(evaluations map[string]int) uint64 {
	var n uint64
	for e, k := range evaluations {
		n += uint64(len(e))*compilePerByte + maxCost*uint64(max(k, 1))
	}
	return n
}

// within reports whether conditions a check reads together, after a change has left them so from
// before, cost what a check may spend on them at most, or, as conditions stored past that before
// there were bounds may, add no condition and none evaluated more: so none is stored past it, and
// what was can be stored again as it is.
func within(before, after map[string]int) bool {
	if most(after) <= maxCheckCost {
		return true
	}
	for e, n := range after {
		if was, ok := before[e]; !ok || n > was {
			return false
		}
	}
	return true
}

// once is each of exprs evaluated once, as a check of one permission evaluates them.
func once(exprs []string) map[string]int {
	evaluations := map[string]int{}
	for _, e := range exprs {
		if e != "" {
			evaluations[e] = 1
		}
	}
	return evaluations
}

// cheapestFirst sorts xs in the order checks evaluate their conditions, which expression reads: by
// what compiling them costs, then by their text, as the same condition decides the same, so a
// check evaluating them in this order decides whatever their ids.
func cheapestFirst[T any](xs []T, expression func(T) string) {
	slices.SortStableFunc(xs, func(x, y T) int {
		ex, ey := expression(x), expression(y)
		return cmp.Or(cmp.Compare(len(ex), len(ey)), strings.Compare(ex, ey))
	})
}

func (b Binding) expression() string { return b.Condition.Expression }

func (b *budget) spend(cost uint64) { b.left -= min(cost, b.left) }

// conditions compiles conditions once and keeps the programs, bounded.
type conditions struct {
	env *cel.Env
	// typed checks a condition against the declared attributes; nil when none are declared.
	typed    *cel.Env
	mu       sync.RWMutex
	programs map[string]program
	// size is the length of the expressions programs holds.
	size int
}

// program is a condition compiled, and why it doesn't check against the attributes declared now,
// if it doesn't: one stored under other declarations, as before an attribute was declared another
// type or no longer, would otherwise run as if they hadn't changed, and a deny reading it as a
// string lift for a list, so a check reads it as failing.
type program struct {
	cel.Program
	typed error
	// readsAction is whether it reads the action, or might, so it can decide apart for each.
	readsAction bool
}

func newConditions(attrs Attributes) (*conditions, error) {
	typed, err := typing(attrs)
	if err != nil {
		return nil, err
	}
	untyped := cel.MapType(cel.StringType, cel.DynType)
	env, err := cel.NewEnv(
		cel.ParserRecursionLimit(maxDepth),
		cel.Variable("subject", untyped),
		cel.Variable("resource", untyped),
		cel.Variable("request", untyped),
		cel.Variable("action", cel.StringType),
	)
	if err != nil {
		return nil, err
	}
	return &conditions{env: env, typed: typed, programs: map[string]program{}}, nil
}

// check returns why an expression can't be stored as a condition: it doesn't compile, or reads
// an attribute it doesn't declare, or as another type. It caches no program it compiles: a change
// checks each of its conditions once, keeping what it found, and one change's conditions would
// otherwise evict the programs checks read, though no check may read them.
func (c *conditions) check(expr string) error {
	prg, ok := c.cached(expr)
	if !ok {
		var err error
		if prg, err = c.build(expr); err != nil {
			return err
		}
	}
	return prg.typed
}

var errCondition = errors.New("rbac: condition")

// cached returns the program checks keep for expr, if they keep one.
func (c *conditions) cached(expr string) (program, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	prg, ok := c.programs[expr]
	return prg, ok
}

// compile returns an expression's program, or why it isn't a condition, and keeps the program.
func (c *conditions) compile(expr string) (program, error) {
	if prg, ok := c.cached(expr); ok {
		return prg, nil
	}
	prg, err := c.build(expr)
	if err != nil {
		return program{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.programs[expr]; ok {
		return prg, nil
	}
	// Bounded: conditions are data, so a tenant could store many. Those evicted are picked at
	// random, so a tenant cycling through new conditions can't evict every other tenant's at once.
	for k := range c.programs {
		if c.size+len(expr) <= maxCached {
			break
		}
		delete(c.programs, k)
		c.size -= len(k)
	}
	c.programs[expr] = prg
	c.size += len(expr)
	return prg, nil
}

// build compiles an expression, or returns why it isn't a condition.
func (c *conditions) build(expr string) (program, error) {
	if len(expr) > MaxExpression {
		return program{}, fmt.Errorf("%w: longer than %d bytes", errCondition, MaxExpression)
	}
	checked, iss := c.env.Compile(expr)
	if iss.Err() != nil {
		return program{}, fmt.Errorf("%w: %w", errCondition, iss.Err())
	}
	if checked.OutputType() != cel.BoolType {
		return program{}, fmt.Errorf("%w: is %s, not a bool", errCondition, checked.OutputType())
	}
	patterns, err := checkPatterns(checked)
	if err != nil {
		return program{}, fmt.Errorf("%w: %w", errCondition, err)
	}
	prg, err := c.env.Program(checked, cel.CostLimit(maxCost), cel.CostTracking(costs{patterns}),
		cel.OptimizeRegex(matching(patterns)), cel.CustomDecorator(bounded))
	if err != nil {
		return program{}, fmt.Errorf("%w: %w", errCondition, err)
	}
	return program{Program: prg, typed: c.typeCheck(expr), readsAction: reading(checked.NativeRep(), "action")}, nil
}

// typeCheck returns why expr doesn't check against the declared attributes: it reads one they
// don't declare, or as another type.
func (c *conditions) typeCheck(expr string) error {
	if c.typed == nil {
		return nil
	}
	checked, iss := c.typed.Compile(expr)
	if iss.Err() != nil {
		return fmt.Errorf("%w: %w", errCondition, iss.Err())
	}
	if checked.OutputType() != cel.BoolType {
		return fmt.Errorf("%w: is %s, not a bool", errCondition, checked.OutputType())
	}
	return nil
}

// costs charges calls by what they read where CEL's own estimate undercounts it: that counts a
// list or map by its length, whatever it holds, a call on an attribute, whose type is known only
// when it runs, as 1 however long a string it reads, and a pattern by a quarter of its length,
// though a repeat makes it compile to many times more instructions. patterns are the sizes of the
// condition's patterns.
type costs struct{ patterns map[string]uint64 }

func (c costs) CallCost(function, _ string, args []ref.Val, _ ref.Val) *uint64 {
	n := uint64(1)
	switch function {
	case overloads.Matches:
		if len(args) != 2 {
			return nil
		}
		n = matchCost(args[0], c.size(args[1]))
	case operators.Equals, operators.NotEquals, operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals, operators.In:
		if len(args) != 2 {
			return nil
		}
		n += comparing(function, args[0], args[1])
	case operators.Add, overloads.Size, overloads.TypeConvertInt, overloads.TypeConvertUint, overloads.TypeConvertDouble,
		overloads.TypeConvertBool, overloads.TypeConvertString, overloads.TypeConvertBytes,
		overloads.TypeConvertTimestamp, overloads.TypeConvertDuration:
		// These read strings and bytes whole, and lists and maps by their length.
		for _, v := range args {
			n += textSize(v)
		}
	case overloads.TimeGetFullYear, overloads.TimeGetMonth, overloads.TimeGetDayOfYear, overloads.TimeGetDate,
		overloads.TimeGetDayOfMonth, overloads.TimeGetDayOfWeek, overloads.TimeGetHours, overloads.TimeGetMinutes,
		overloads.TimeGetSeconds, overloads.TimeGetMilliseconds:
		if len(args) < 2 {
			return nil
		}
		n = zoneCost
	default:
		return nil
	}
	return &n
}

// comparing is what comparing x with y, or finding x in y, reads, counted no further than past
// maxCost. Comparing stops at the smaller value; a map finds a key without reading the rest.
func comparing(function string, x, y ref.Val) uint64 {
	if function != operators.In {
		return smaller(x, y, maxCost)
	}
	if _, isMap := y.(traits.Mapper); isMap {
		return valueSize(x, maxCost)
	}
	return valueSize(y, maxCost)
}

// bounded refuses, before running it, a comparison or a search in a list that would read more than
// a condition may: one call reads it all, and a call's cost is counted only once it has run, so a
// list a condition doubles cheaply would otherwise hold a check for as long as walking it takes.
// It refuses a comparison of a double that isn't finite too (nonFinite).
func bounded(i interpreter.Interpretable) (interpreter.Interpretable, error) {
	call, ok := i.(interpreter.InterpretableCall)
	if !ok {
		return i, nil
	}
	var op func(x, y ref.Val) ref.Val
	switch call.Function() {
	case operators.Equals:
		op = equal
	case operators.NotEquals:
		op = func(x, y ref.Val) ref.Val {
			eq := equal(x, y)
			if b, ok := eq.(types.Bool); ok {
				return !b
			}
			return eq
		}
	case operators.In:
		op = func(x, y ref.Val) ref.Val {
			if l, ok := y.(traits.Lister); ok {
				return contains(l, x)
			}
			if c, ok := y.(traits.Container); ok {
				return c.Contains(x)
			}
			return types.NoSuchOverloadErr()
		}
	case operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals:
		op = ordering(call.Function())
	default:
		return i, nil
	}
	function := call.Function()
	return interpreter.NewCall(call.ID(), function, call.OverloadID(), call.Args(), func(args ...ref.Val) ref.Val {
		if len(args) != 2 {
			return types.NoSuchOverloadErr()
		}
		if comparing(function, args[0], args[1]) > maxCost {
			return types.NewErr("rbac: comparing values this large costs more than a condition may")
		}
		if nonFinite(args[0]) || nonFinite(args[1]) {
			return incomparable()
		}
		return op(args[0], args[1])
	}), nil
}

// ordering is x compared with y by an ordering operator, as CEL orders them, once bounded has
// refused a double that isn't finite.
func ordering(function string) func(x, y ref.Val) ref.Val {
	return func(x, y ref.Val) ref.Val {
		c, ok := x.(traits.Comparer)
		if !ok {
			return types.MaybeNoSuchOverloadErr(x)
		}
		cmp := c.Compare(y)
		n, ok := cmp.(types.Int)
		if !ok {
			return cmp
		}
		switch function {
		case operators.Less:
			return types.Bool(n < 0)
		case operators.LessEquals:
			return types.Bool(n <= 0)
		case operators.Greater:
			return types.Bool(n > 0)
		default:
			return types.Bool(n >= 0)
		}
	}
}

// nonFinite reports whether v is a double that isn't finite, which a condition makes of finite ones
// dividing by zero or converting "NaN". CEL orders and equates NaN as false with anything, so a
// deny's `failed / total >= 0.5` would lift where both are 0.0, and -Inf orders below every
// bound, so comparing either fails, as a declared double that isn't finite does.
func nonFinite(v ref.Val) bool {
	d, ok := v.(types.Double)
	return ok && (math.IsNaN(float64(d)) || math.IsInf(float64(d), 0))
}

func incomparable() ref.Val {
	return types.NewErr("rbac: a double that isn't finite can't be compared")
}

// equal is x == y, failing where comparing values a map or list holds fails, as reading a
// declared attribute passed as another type does: CEL's own comparison of maps and lists counts
// such a value as equal, so that a map holding one would equal any map with its keys.
func equal(x, y ref.Val) ref.Val {
	if types.IsUnknownOrError(x) {
		return x
	}
	if types.IsUnknownOrError(y) {
		return y
	}
	// By their sizes alone, CEL's comparison would tell a refused name from one never passed.
	if refusing(x) || refusing(y) {
		return refusal()
	}
	// As a list or map holds it too.
	if nonFinite(x) || nonFinite(y) {
		return incomparable()
	}
	var failed ref.Val
	same := func(a, b ref.Val) bool {
		eq := equal(a, b)
		if eq != types.False && eq != types.True && failed == nil {
			failed = eq
		}
		return eq != types.False
	}
	switch xs := x.(type) {
	case traits.Mapper:
		ys, ok := y.(traits.Mapper)
		if !ok || xs.Size() != ys.Size() {
			return types.Equal(x, y)
		}
		for it := xs.Iterator(); it.HasNext() == types.True; {
			k := it.Next()
			b, found := ys.Find(k)
			if !found {
				return types.False
			}
			if a, _ := xs.Find(k); !same(a, b) {
				return types.False
			}
		}
	case traits.Lister:
		ys, ok := y.(traits.Lister)
		n, sized := xs.Size().(types.Int)
		if !ok || !sized || ys.Size() != n {
			return types.Equal(x, y)
		}
		for i := types.Int(0); i < n; i++ {
			if !same(xs.Get(i), ys.Get(i)) {
				return types.False
			}
		}
	default:
		return types.Equal(x, y)
	}
	if failed != nil {
		return failed
	}
	return types.True
}

// contains is x in l, failing where comparing x with a value l holds fails and none equals it.
func contains(l traits.Lister, x ref.Val) ref.Val {
	var failed ref.Val
	for it := l.Iterator(); it.HasNext() == types.True; {
		switch eq := equal(x, it.Next()); {
		case eq == types.True:
			return eq
		case eq != types.False && failed == nil:
			failed = eq
		}
	}
	if failed != nil {
		return failed
	}
	return types.False
}

// smaller is the smaller of two values' sizes, counted no further than past limit. It reads both
// as far as each other, doubling how far until one is read whole, so that charging for comparing a
// large value with a small one, which is cheap, is cheap too.
func smaller(x, y ref.Val, limit uint64) uint64 {
	for l := uint64(1); ; l = min(2*l, limit) {
		sx, sy := valueSize(x, l), valueSize(y, l)
		if sx <= l || sy <= l || l == limit {
			return min(sx, sy)
		}
	}
}

// valueSize is the cost of reading v whole, nested values included, counted no further than
// past limit: one for each value, and a tenth of a string's or bytes' length. A list or map too
// long to be within limit is past it unread, since iterating a map copies all its keys.
func valueSize(v ref.Val, limit uint64) uint64 {
	n := textSize(v)
	switch v := v.(type) {
	case traits.Mapper:
		// Each entry is at least a key and a value.
		if least := n + 2*count(v); least > limit {
			return least
		}
		for it := v.Iterator(); n <= limit && it.HasNext() == types.True; {
			k := it.Next()
			n += valueSize(k, limit-n) + valueSize(v.Get(k), limit-n)
		}
	case traits.Lister:
		if least := n + count(v); least > limit {
			return least
		}
		for it := v.Iterator(); n <= limit && it.HasNext() == types.True; {
			n += valueSize(it.Next(), limit-n)
		}
	}
	return n
}

func count(v traits.Sizer) uint64 {
	n, _ := v.Size().(types.Int)
	return uint64(max(n, 0))
}

func textSize(v ref.Val) uint64 {
	switch v := v.(type) {
	case types.String:
		return 1 + uint64(len(v))/10
	case types.Bytes:
		return 1 + uint64(len(v))/10
	}
	return 1
}

// size is about how many instructions pattern compiles to.
func (c costs) size(pattern ref.Val) uint64 {
	if p, ok := pattern.(types.String); ok {
		if n, ok := c.patterns[string(p)]; ok {
			return n
		}
	}
	return maxPattern
}

// matchCost is what matching s against a pattern of size instructions costs: matching steps
// through each instruction for each character, as CEL's own estimate has it for the instructions
// it guesses.
func matchCost(s ref.Val, size uint64) uint64 { return textSize(s) * size }

// matching compiles a condition's patterns once, and refuses a match that would cost more than a
// whole condition may before running it: a call's cost is counted only once it has run.
func matching(patterns map[string]uint64) *interpreter.RegexOptimization {
	return &interpreter.RegexOptimization{
		Function: overloads.Matches, RegexIndex: 1,
		Factory: func(call interpreter.InterpretableCall, pattern string) (interpreter.InterpretableCall, error) {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			size := costs{patterns}.size(types.String(pattern))
			return interpreter.NewCall(call.ID(), call.Function(), call.OverloadID(), call.Args(), func(args ...ref.Val) ref.Val {
				if len(args) != 2 {
					return types.NoSuchOverloadErr()
				}
				in, ok := args[0].(types.String)
				if !ok {
					return types.NoSuchOverloadErr()
				}
				if matchCost(in, size) > maxCost {
					return types.NewErr("rbac: matching a string this long costs more than a condition may")
				}
				return types.Bool(re.MatchString(string(in)))
			}), nil
		},
	}
}

// checkPatterns requires each pattern a condition matches to be a string literal, so its size is
// known when the condition is granted, bounds their size together, and returns each one's.
func checkPatterns(checked *cel.Ast) (map[string]uint64, error) {
	sizes := map[string]uint64{}
	var total uint64
	for _, e := range ast.MatchDescendants(ast.NavigateAST(checked.NativeRep()), ast.FunctionMatcher(overloads.Matches)) {
		args := e.AsCall().Args()
		lit, ok := args[len(args)-1].AsLiteral().(types.String)
		if !ok {
			return nil, errors.New("a pattern is a string literal")
		}
		re, err := syntax.Parse(string(lit), syntax.Perl)
		if err != nil {
			return nil, err
		}
		size := patternSize(re)
		if total += size; total > maxPattern {
			return nil, fmt.Errorf("its patterns are larger than %d", maxPattern)
		}
		sizes[string(lit)] = size
	}
	return sizes, nil
}

// patternSize is about how many instructions re compiles to, a literal one per character and a
// repeat counting what it repeats as often as it may, and stops counting past maxPattern.
func patternSize(re *syntax.Regexp) uint64 {
	n := uint64(1)
	if re.Op == syntax.OpLiteral {
		n += uint64(len(re.Rune))
	}
	for _, sub := range re.Sub {
		n += patternSize(sub)
	}
	if re.Op == syntax.OpRepeat {
		n *= uint64(max(re.Min, re.Max, 1))
	}
	return min(n, maxPattern+1)
}

// holds evaluates a condition on a request, spending from b; one that fails, or that b can't
// pay for, is false.
func (c *conditions) holds(b *budget, expr string, vars map[string]any) bool {
	held, _ := c.decide(b, expr, vars)
	return held
}

// decide evaluates a condition on a request, spending from b, and reports whether it held and
// whether it could be evaluated at all, as a deny fails closed where it couldn't.
func (c *conditions) decide(b *budget, expr string, vars map[string]any) (held, evaluated bool) {
	// The action is all that a budget's requests differ in.
	action, _ := vars["action"].(string)
	key := action + "\x00" + expr
	if d, ok := b.decided[key]; ok {
		return d.held, d.evaluated
	}
	defer func() { b.decided[key] = decision{held, evaluated} }()
	if b.left == 0 {
		b.exhausted = true
		return false, false
	}
	// A check pays to compile each condition once, whether or not it is cached, so what it decides
	// doesn't depend on what the cache holds: other tenants' conditions can evict this one's.
	if !b.compiled[expr] {
		b.compiled[expr] = true
		b.spend(uint64(len(expr)) * compilePerByte)
	}
	if b.left == 0 {
		b.exhausted = true
		return false, false
	}
	prg, err := c.compile(expr)
	if err != nil || prg.typed != nil {
		return false, false
	}
	ranKey := expr
	if prg.readsAction {
		ranKey = key
	}
	r, ok := b.ran[ranKey]
	if !ok {
		r = evaluate(prg, vars)
		if b.ran != nil {
			b.ran[ranKey] = r
		}
	}
	left := b.left
	b.spend(r.cost)
	// One that cost more than was left is past the budget too.
	if r.cost > left {
		b.exhausted = true
		return false, false
	}
	return r.held, r.evaluated
}

// evaluating runs as a condition is evaluated, as a test's counter.
var evaluating = func() {}

// evaluate runs a condition's program on a request.
func evaluate(prg program, vars map[string]any) run {
	evaluating()
	out, details, err := prg.Eval(vars)
	// One stopped at its limit costs at most that, past the call that took it there, so a single
	// condition can't spend what the check's others need.
	cost := uint64(maxCost)
	if details != nil && details.ActualCost() != nil {
		cost = min(*details.ActualCost(), maxCost)
	}
	if err != nil {
		return run{cost: cost}
	}
	ok, isBool := out.Value().(bool)
	return run{held: isBool && ok, evaluated: isBool, cost: cost}
}

// parsing parses conditions for what they read, which needs no declarations.
var parsing, _ = cel.NewEnv()

// readsSubject reports whether expr reads the subject, or might: one that doesn't parse might.
func readsSubject(expr string) bool { return reads(expr, "subject") }

// reads reports whether expr reads the variable name, or might: one that doesn't parse might.
func reads(expr, name string) bool {
	parsed, iss := parsing.Parse(expr)
	return iss.Err() != nil || reading(parsed.NativeRep(), name)
}

// reading reports whether an expression names the variable name, as a variable of a macro of its
// own does too.
func reading(e *ast.AST, name string) bool {
	// `.name` names it from the root, as `name` does.
	return len(ast.MatchDescendants(ast.NavigateAST(e), func(e ast.NavigableExpr) bool {
		return e.Kind() == ast.IdentKind && strings.TrimPrefix(e.AsIdent(), ".") == name
	})) > 0
}

type requestKey struct{}

// WithRequest returns ctx carrying the attributes of the request it serves, such as its
// address or whether it passed a second factor, which conditions read as request.attributes.
// Values are what CEL reads: strings, numbers, booleans, times, and lists and maps of them.
func WithRequest(ctx context.Context, attributes map[string]any) context.Context {
	return context.WithValue(ctx, requestKey{}, maps.Clone(attributes))
}

// vars is what a condition reads when s asks to do p to r.
func (a *Authorizer) vars(ctx context.Context, s Subject, p Permission, r Resource) map[string]any {
	request, _ := ctx.Value(requestKey{}).(map[string]any)
	return map[string]any{
		"subject":  map[string]any{"kind": string(s.Principal.Kind), "id": s.Principal.ID, "attributes": declared(a.cfg.Attributes.Subject, s.Attributes)},
		"resource": map[string]any{"type": r.Type, "id": r.ID, "tenant": r.Tenant, "attributes": declared(a.cfg.Attributes.Resource, r.Attributes)},
		"request":  map[string]any{"time": a.cfg.Now(), "attributes": declared(a.cfg.Attributes.Request, request)},
		"action":   string(p),
	}
}

// declared is attributes as conditions read them: each one as declares it, passed as another Go
// value than its type takes or as none, and each one a declared kind doesn't declare, made an
// error that whatever reads it fails on, comparing it included, as one not passed is. CEL compares values of different types as unequal rather
// than fail, so otherwise a `!=` would hold for it, and a deny's `==` would lift. A kind not
// declared is as passed.
func declared(declares map[string]AttributeType, attributes map[string]any) any {
	attributes = orEmpty(attributes)
	if declares == nil {
		return attributes
	}
	var typed map[string]any
	for name, v := range attributes {
		t, ok := declares[name]
		if ok && t.takes(v) {
			continue
		}
		if typed == nil {
			typed = maps.Clone(attributes)
		}
		// One it doesn't declare a condition reads only through dyn(), which no type is checked by
		// when stored, so it fails as one of another type does.
		if ok {
			typed[name] = types.NewErr("rbac: attribute %q is not a %s", name, t)
		} else {
			typed[name] = types.NewErr("rbac: attribute %q is not declared", name)
		}
	}
	if typed == nil {
		return attributes
	}
	return refusedAttributes{types.NewStringInterfaceMap(types.DefaultTypeAdapter, typed)}
}

// refusedAttributes are a kind's attributes with some refused, as conditions read them. A refused
// one fails what reads it by name, as CEL fails a value that is an error, and so does a test of
// its presence, which CEL reads from a map's keys alone and which would otherwise hold. Whatever
// reads the map as a whole, in, size(), the macros and comparing it, fails too, as it could tell a
// refused name from one never passed.
type refusedAttributes struct {
	traits.Mapper
}

// refusedAttributesType has none of a map's traits, so CEL has no size(), in or macro for it.
var refusedAttributesType = types.NewOpaqueType("rbac.RefusedAttributes")

func (refusedAttributes) Type() ref.Type { return refusedAttributesType }

// Contains fails, for the bounded decorator, which finds in by a map's own method.
func (refusedAttributes) Contains(ref.Val) ref.Val { return refusal() }

func refusing(v ref.Val) bool {
	_, ok := v.(refusedAttributes)
	return ok
}

// refusal is a new error each time, as CEL labels an error with the node it was raised at.
func refusal() ref.Val { return types.NewErr("rbac: the attributes hold one refused") }

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
