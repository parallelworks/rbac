package rbac

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
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
// as one reading an attribute the host didn't pass does, is false. The zero Condition is none,
// and one with a title or description has an expression. A pattern it matches is a string
// literal, of bounded size. A check spends a bounded budget on its grants' conditions and another,
// for each scope on its path, on its denies', compiling them included: past it, a grant's
// condition is false and a deny's applies, so what still needs one is refused. A check evaluates
// the cheapest first, so what it decides doesn't rest on ids, and SetDeny bounds a scope's
// conditional denies together so that a check always evaluates them whole.
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
	// maxCheckCost is what one check may spend on its grants' conditions, compiling included, and a
	// listing or a change on each permission it decides, so many conditional grants on one path
	// can't make it slow: once it is spent, no further condition holds, and what needs one is
	// refused.
	maxCheckCost = 8 * maxCost
	// compilePerByte is what compiling a condition costs for each byte of it: compiling one
	// takes about as long as evaluating eight units of cost for each.
	compilePerByte = 8
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
}

// decision is what evaluating a condition decided.
type decision struct{ held, evaluated bool }

func newBudget() *budget { return budgetOf(maxCheckCost) }

// newDenyBudget is a check's budget for the denies' conditions on a path of scopes, apart from
// what it spends on its grants', so neither leaves the other nothing: a scope's conditional denies
// cost at most maxCheckCost together (SetDeny), so a check may spend that much for each scope of
// its path, and evaluates them whole however deep it is.
func newDenyBudget(path []string) *budget { return budgetOf(uint64(len(path)) * maxCheckCost) }

func budgetOf(left uint64) *budget {
	return &budget{left: left, compiled: map[string]bool{}, decided: map[string]decision{}}
}

// worstCost is the most a condition can cost a check: compiling it, and evaluating it to its bound.
func worstCost(expr string) uint64 { return uint64(len(expr))*compilePerByte + maxCost }

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
	// typed checks a condition against the declared attributes when it is stored; nil when none
	// are declared. typedOK are the expressions it passed, bounded as the programs are, so a change
	// storing one condition many times checks it once.
	typed    *cel.Env
	mu       sync.RWMutex
	programs map[string]cel.Program
	cached   int
	typedOK  map[string]bool
	typedLen int
}

func newConditions(attrs Attributes) (*conditions, error) {
	typed, err := typing(attrs)
	if err != nil {
		return nil, err
	}
	untyped := cel.MapType(cel.StringType, cel.DynType)
	env, err := cel.NewEnv(
		cel.Variable("subject", untyped),
		cel.Variable("resource", untyped),
		cel.Variable("request", untyped),
		cel.Variable("action", cel.StringType),
	)
	if err != nil {
		return nil, err
	}
	return &conditions{env: env, typed: typed, programs: map[string]cel.Program{}, typedOK: map[string]bool{}}, nil
}

// check returns why an expression can't be stored as a condition: it doesn't compile, or reads
// an attribute it doesn't declare, or as another type.
func (c *conditions) check(expr string) error {
	if _, err := c.compile(expr); err != nil || c.typed == nil {
		return err
	}
	c.mu.RLock()
	ok := c.typedOK[expr]
	c.mu.RUnlock()
	if ok {
		return nil
	}
	checked, iss := c.typed.Compile(expr)
	if iss.Err() != nil {
		return fmt.Errorf("%w: %w", errCondition, iss.Err())
	}
	if checked.OutputType() != cel.BoolType {
		return fmt.Errorf("%w: is %s, not a bool", errCondition, checked.OutputType())
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.typedOK {
		if c.typedLen+len(expr) <= maxCached {
			break
		}
		delete(c.typedOK, k)
		c.typedLen -= len(k)
	}
	if !c.typedOK[expr] {
		c.typedOK[expr] = true
		c.typedLen += len(expr)
	}
	return nil
}

var errCondition = errors.New("rbac: condition")

// compile returns an expression's program, or why it isn't a condition.
func (c *conditions) compile(expr string) (cel.Program, error) {
	c.mu.RLock()
	prg, ok := c.programs[expr]
	c.mu.RUnlock()
	if ok {
		return prg, nil
	}
	return c.build(expr)
}

func (c *conditions) build(expr string) (cel.Program, error) {
	if len(expr) > MaxExpression {
		return nil, fmt.Errorf("%w: longer than %d bytes", errCondition, MaxExpression)
	}
	checked, iss := c.env.Compile(expr)
	if iss.Err() != nil {
		return nil, fmt.Errorf("%w: %w", errCondition, iss.Err())
	}
	if checked.OutputType() != cel.BoolType {
		return nil, fmt.Errorf("%w: is %s, not a bool", errCondition, checked.OutputType())
	}
	patterns, err := checkPatterns(checked)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCondition, err)
	}
	prg, err := c.env.Program(checked, cel.CostLimit(maxCost), cel.CostTracking(costs{patterns}),
		cel.OptimizeRegex(matching(patterns)))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errCondition, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.programs[expr]; ok {
		return prg, nil
	}
	// Bounded: conditions are data, so a tenant could store many. Those evicted are picked at
	// random, so a tenant cycling through new conditions can't evict every other tenant's at once.
	for k := range c.programs {
		if c.cached+len(expr) <= maxCached {
			break
		}
		delete(c.programs, k)
		c.cached -= len(k)
	}
	c.programs[expr] = prg
	c.cached += len(expr)
	return prg, nil
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
	case operators.Equals, operators.NotEquals, operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals:
		// Comparing stops at the smaller value.
		if len(args) == 2 {
			n += smaller(args[0], args[1], maxCost)
		}
	case operators.In:
		if len(args) != 2 {
			return nil
		}
		// A map finds a key without reading the rest.
		if _, isMap := args[1].(traits.Mapper); isMap {
			n += valueSize(args[0], maxCost)
		} else {
			n += valueSize(args[1], maxCost)
		}
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
	if err != nil {
		return false, false
	}
	left := b.left
	out, details, err := prg.Eval(vars)
	cost := uint64(maxCost)
	if details != nil && details.ActualCost() != nil {
		cost = *details.ActualCost()
	}
	b.spend(cost)
	// One that cost more than was left is past the budget too.
	if cost > left {
		b.exhausted = true
	}
	if err != nil || cost > left {
		return false, false
	}
	ok, isBool := out.Value().(bool)
	return isBool && ok, isBool
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
		"subject":  map[string]any{"kind": string(s.Principal.Kind), "id": s.Principal.ID, "attributes": orEmpty(s.Attributes)},
		"resource": map[string]any{"type": r.Type, "id": r.ID, "tenant": r.Tenant, "attributes": orEmpty(r.Attributes)},
		"request":  map[string]any{"time": a.cfg.Now(), "attributes": orEmpty(request)},
		"action":   string(p),
	}
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}
