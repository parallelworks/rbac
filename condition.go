package rbac

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"math/bits"
	"reflect"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/cost"
	"cel.dev/cel-go/common/functions"
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
// A grant with one gives its role only where the expression is true. An expression that fails, as
// one reading an attribute the host didn't pass does, or comparing a double that isn't finite, as
// dividing by zero makes, converting one to a string, keying a map by one or building a list or a
// map holding one, so no list or map a condition reads holds one, or building a map that names a
// key twice, is false. What the host passes is converted into CEL's own
// values, the subject's and the request's attributes once for a call and a resource's once for each
// check of it, from the values Attributes names, and a kind's attributes holding anything else
// can't be read, every condition reading one of them failing, a test of its presence too, and so
// does one keying a map by them, comparing them or finding them in a list, building a list or a map
// holding them, or reading the subject, the resource or the request holding them whole, so
// conditions read CEL's own values alone, at what reading any value of its size costs; an attribute
// holding a double that isn't finite, however deep, fails whatever reads it, and whatever reads its
// kind whole, and where no declarations cover its kind, the kind's attributes can't be read, as
// where they hold anything else. A label
// value and a power to release are decided on the tenant with no attributes, whatever a check
// passes (Holding), and their conditions can't read the tenant's: any read of resource.attributes
// fails, a test of an attribute's presence, in, size(), a macro and a comparison included, and so
// does reading the resource whole, so a grant's gives nothing and a deny's applies. The zero
// Condition is none, and one with a title or description has an expression. A pattern it matches
// is a string literal,
// of bounded size; it nests at most 32 deep; it builds no message, as `google.protobuf.Struct{}`;
// it indexes a variable it names from the root where a loop's variable of the same name hides it,
// as `.request` in `l.all(request, ...)`, by literals alone; and a comparison, or a search of a
// list, that would read more than a condition may spend, or reading a time in a zone whose name is
// longer than 64 bytes, holds a byte no zone's name does, as
// tzdata.zi's dot, or has a part that is Local, the zone the process runs in, or localtime, in any
// case, as posix/localtime, fails before it runs. request.time is the host's clock (Config.Now) in
// UTC, and a time the host passes is read in UTC too (Attributes), so string() of one writes the
// same in every replica, whatever zone each runs in. It wrote a time the host passed in the time's
// own zone before, so a condition comparing that with text written at the zone's offset no longer
// holds; comparing times, and reading their parts, decide as before.
//
// Each condition runs within the most evaluating it can cost, which its literals and types bound:
// little for one comparing what a request passes with literals, or with the subject's kind or id,
// the resource's type, id or tenant, or the action, which a check refuses past MaxID bytes,
// whatever it passes, and all a condition may for one reading the size of a value the request
// decides, as a list or a long string, looking one up in a map, or looping over one, each element
// of which costs at least 1 however little its step evaluates, and 1 more for each logical operator
// or choice it may, and each key of a map 1 more each time a loop over it starts, however few steps
// it takes. A loop over a map gives its keys in one order, whatever order the map's entries come
// in: bools, ints, uints, doubles, strings and then bytes, each by its value, strings and bytes by
// their bytes, so `{"b": 1, "a": 2}.map(k, k)` is `["a", "b"]`. Sorting them costs 1 for each two
// keys each time their number halves to one, and each key what reading it does past 1, once, before
// the loop starts, and a loop over a map holding more than one key of another type, as a literal
// keyed by lists can, fails.
// A list or map literal costs 1 more for each element, or 2 for each entry, each time it
// is built, and contains, startsWith and endsWith cost reading what they search, at least 1 however
// short either string is, and fail before they run where they would cost more than a condition may.
// A comparison costs reading the smaller value, charged as it is read, once, before it runs.
// Reading a time in a zone costs 100, and 500 more where an attribute names the zone, each time,
// whether or not the process has loaded it, so a check decides alike whatever zones the process
// loaded before: the process loads each zone once, and finds a name names none once, the zone a
// literal names when the condition is planned, and one an attribute names the first time a time is
// read in it, which a request can make a new one each time; but where reading the platform's files
// failed, as once the process ran out of file descriptors, it keeps nothing and loads the zone again
// the next time. request.time costs what a timestamp does, as it always is one.
// What a check may spend on conditions is bounded, for each scope on its path, and so are the
// conditions stored, so that a check evaluates whole every one it reads: those of an identity's
// grants on a scope cost at most so much together, and those of a scope's grants to groups, the
// tenant's members and the public, which reach many, as much again, those from each source the
// host owns (Config.Sources) apart from the rest; those of a scope's denies (SetDeny); and the
// requirements of the eligibilities of groups for a role on a scope. Each distinct condition counts
// once, as what compiling it and the most evaluating it can cost:
// hundreds of comparisons with literals, a hundred of an attribute with the subject's id, or three
// of the longest that read a list or loop. A check of a labeled resource decides each value its
// label asks for, and Holding, Filter and Reachable each of the subject's label values, as a check
// of it would, evaluating a condition that doesn't read the action once for them all, so on the
// tenant one that does counts once for each label value its grants give or its denies deny. A
// change checking the labels of many scopes by one read of its actor's values decides each value
// once, when a label first asks for it, and evaluates such a condition once for all of them in each
// of its phases: each value is still decided on a budget of its own, which pays for every condition
// it reads, whether it ran it or a value before it did, so it decides as a check of it would. A
// change adding a condition past a bound, or one evaluated more, as by redefining a role to give
// more label values (SetRole), is refused as invalid, so no grant, deny or eligibility stored
// changes what the others decide, but one adding none isn't: conditions stored past a bound before
// there were bounds can be rewritten in place, as by a restore over the rows still stored, though
// restored where those are gone, they are added, and refused. An upgrade of CEL, or of this package
// where it bounds a shape more, can leave conditions stored past a bound in the same way: each
// process bounds a condition by what it and the CEL it is built with make of it, its macros and
// types, and another version may bound one stored more. A check may not reach all of those, or of
// those of a role a catalog change widened since: it evaluates the cheapest first, and past its
// budget a grant's condition is false and a deny's applies.
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
	// hold gigabytes. maxLimits bounds the limits kept so.
	maxCached = 256 << 10
	maxLimits = 2 << 20
	// zoneCost is what reading a time in a named zone costs once the process has loaded the zone
	// (zones), and zoneLoad what reading one in a zone an attribute names costs more, loaded or not
	// (inZone), about what loading one from the platform's zone files takes, or finding a name names
	// none, which looks in four places: thirty microseconds. Loading copies the name for each place it
	// looks, so a zone is at most maxZone bytes, more than the longest name a time zone has. maxZones
	// bounds the zones the process keeps loaded, and the names it found name none: the time zone
	// database names about six hundred.
	zoneCost = 100
	zoneLoad = 500
	maxZone  = 64
	maxZones = 1024
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
	// listing's budgets for each permission share, and a change's for each label value it decides by
	// one read of its actor's (runs): each pays for a condition as if it evaluated it, so it decides
	// as a check of its permission would, but one that doesn't read the action runs once for them
	// all. nil for a budget that shares none, whose one request decided covers.
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

// most is what a check can spend on conditions, counted no further than past maxCheckCost: each
// compiled once, and evaluated as many times as evaluations has it, and at least once, each time
// costing at most what limit says. It stops there: conditions stored past the bound before there
// were bounds can be many, and a change learns their limits by compiling them, under its locks.
func most(evaluations map[string]int, limit func(string) uint64) uint64 {
	var n uint64
	for e, k := range evaluations {
		if n > maxCheckCost {
			break
		}
		n = cost.SafeAdd(n, cost.SafeAdd(uint64(len(e))*compilePerByte, cost.SafeMultiply(limit(e), uint64(max(k, 1)))))
	}
	return n
}

func atMostMaxCost(string) uint64 { return maxCost }

// within reports whether conditions a check reads together, after a change has left them so from
// before, cost what a check may spend on them at most, or, as conditions stored past that before
// there were bounds may, add no condition and none evaluated more: so none is stored past it, and
// what was can be stored again as it is.
func (c *conditions) within(before, after map[string]int) bool {
	// Most fit however costly each is, and needn't be compiled to tell.
	if most(after, atMostMaxCost) <= maxCheckCost || most(after, c.limit) <= maxCheckCost {
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
	// limits are what evaluating conditions can cost, of those programs holds and more, as a change
	// bounding what a check reads together reads the limit of each condition on a scope, and a
	// limit takes a few bytes where a program takes a hundred times its expression.
	limits     map[string]uint64
	limitsSize int
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
	// limit is the most evaluating it can cost (worstCost), which it runs within, so a check never
	// spends more on it than its bound counted.
	limit uint64
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
	return &conditions{env: env, typed: typed, programs: map[string]program{}, limits: map[string]uint64{}}, nil
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
		c.keepLimit(expr, prg.limit)
	}
	return prg.typed
}

// limit is the most evaluating expr can cost, compiling it where none is kept; nothing for one that
// isn't a condition, which a check refuses once it has paid to compile it.
func (c *conditions) limit(expr string) uint64 {
	c.mu.RLock()
	limit, ok := c.limits[expr]
	c.mu.RUnlock()
	if ok {
		return limit
	}
	prg, err := c.build(expr)
	if err != nil {
		return 0
	}
	c.keepLimit(expr, prg.limit)
	return prg.limit
}

func (c *conditions) keepLimit(expr string, limit uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.keptLimit(expr, limit)
}

// keptLimit is keepLimit with c.mu held.
func (c *conditions) keptLimit(expr string, limit uint64) {
	if _, ok := c.limits[expr]; ok {
		return
	}
	for k := range c.limits {
		if c.limitsSize+len(expr) <= maxLimits {
			break
		}
		delete(c.limits, k)
		c.limitsSize -= len(k)
	}
	c.limits[expr] = limit
	c.limitsSize += len(expr)
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
	c.keptLimit(expr, prg.limit)
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
	// A message literal, as google.protobuf.ListValue{values: ...}, converts the values its fields
	// are given whole, and an Any unpacks its bytes, though CEL charges either a constant however
	// large they are; a value the host passes that holds itself it converts until the stack
	// overflows, which no recover catches. What a condition reads is maps, lists, strings and
	// times, which need none.
	if len(ast.MatchDescendants(ast.NavigateAST(checked.NativeRep()), ast.KindMatcher(ast.StructKind))) > 0 {
		return program{}, fmt.Errorf("%w: it builds a message", errCondition)
	}
	patterns, err := checkPatterns(checked)
	if err != nil {
		return program{}, fmt.Errorf("%w: %w", errCondition, err)
	}
	limit := worstCost(checked, patterns)
	prg, err := plan(c.env, checked, patterns, limit)
	if err != nil {
		return program{}, fmt.Errorf("%w: %w", errCondition, err)
	}
	return program{Program: prg, typed: c.typeCheck(expr), readsAction: reading(checked.NativeRep(), "action"), limit: limit}, nil
}

// plan plans checked to run within limit, as costs charges its calls, once the options before
// have, as a test plans a loop as another version of CEL may.
func plan(env *cel.Env, checked *cel.Ast, patterns map[string]uint64, limit uint64, before ...cel.ProgramOption) (cel.Program, error) {
	if indexedPastLoop(checked.NativeRep()) {
		return nil, errors.New("a variable named from the root past a loop's variable of its name is indexed by a key it computes, which CEL evaluates where nothing charges it")
	}
	s, k := newStepping(checked.NativeRep(), limit), newKeying(env, checked.NativeRep(), limit)
	l, str, g := newLiterals(checked.NativeRep(), limit), &stringing{env: env}, newGuards(checked.NativeRep(), limit)
	prg, err := env.Program(checked, slices.Concat(before, []cel.ProgramOption{
		cel.CostLimit(limit), cel.CostTracking(costs{patterns}), cel.OptimizeRegex(matching(patterns, g)),
		cel.CustomDecorator(g.bounded), cel.CustomDecorator(str.decorate), cel.CustomDecoratorV2(s.decorate),
		cel.CustomDecoratorV2(k.decorate), cel.CustomDecoratorV2(l.decorate), cel.CustomDecoratorV2(s.order),
	})...)
	if err != nil {
		return nil, err
	}
	// Another version of CEL may plan a loop's condition, a key, a literal, or a call refused before
	// it runs where no decorator sees it, which would run unbounded too, and a loop's range where
	// none orders it, which would loop over a map as Go happens to range over it.
	if len(s.stepped) != len(s.ranges) {
		return nil, errors.New("a loop's condition is planned where this package can't bound it")
	}
	if len(s.ordered) != len(s.over) {
		return nil, errors.New("a loop's range is planned where this package can't order a map's keys")
	}
	if len(k.planned) != len(k.keys) {
		return nil, errors.New("a key is planned where this package can't charge it")
	}
	if len(l.planned) != len(l.sizes) {
		return nil, errors.New("a literal is planned where this package can't charge it")
	}
	if len(g.planned) != len(g.ids) {
		return nil, errors.New("a comparison, a search or a match is planned where this package can't bound it")
	}
	return prg, nil
}

// indexedPastLoop reports whether checked indexes a variable it names from the root where a loop's
// variable of the same name hides it, as `.request` in `l.all(request, ...)`, by anything but a
// literal, at once or past selects, indexes and either side of a choice. CEL reads such a variable
// from what the check passed, outside the evaluation, and indexes it there, where nothing is charged,
// so the key and whatever computing it evaluated ran uncharged: a key searching a string costing
// 10,000 at each of 3,000 steps of a loop cost 6,003, and one concatenating strings at each took
// 200 ms where 10,000 covers 1.5 at most. Read there by its fields or literal keys, it reads a value
// for each, uncharged too, but no more than the condition names.
func indexedPastLoop(checked *ast.AST) bool {
	refs := checked.ReferenceMap()
	var rooted func(e ast.Expr) bool
	rooted = func(e ast.Expr) bool {
		switch e.Kind() {
		case ast.IdentKind, ast.SelectKind:
			if ref, ok := refs[e.ID()]; ok {
				return strings.HasPrefix(ref.Name, ".")
			}
			return e.Kind() == ast.SelectKind && !e.AsSelect().IsTestOnly() && rooted(e.AsSelect().Operand())
		case ast.CallKind:
			args := e.AsCall().Args()
			switch fn := e.AsCall().FunctionName(); {
			case fn == operators.Index && len(args) == 2:
				return rooted(args[0])
			case fn == operators.Conditional && len(args) == 3:
				return rooted(args[1]) || rooted(args[2])
			}
		default:
			// A literal, a list, a map or a loop is a value of its own.
		}
		return false
	}
	return len(ast.MatchDescendants(ast.NavigateAST(checked), func(e ast.NavigableExpr) bool {
		if e.Kind() != ast.CallKind || e.AsCall().FunctionName() != operators.Index {
			return false
		}
		args := e.AsCall().Args()
		return len(args) == 2 && args[1].Kind() != ast.LiteralKind && rooted(args[0])
	})) > 0
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
// when it runs, as 1 however long a string it reads, a search of a string by its characters,
// rounded down to nothing where a side is empty, and a pattern by a quarter of its length, though
// a repeat makes it compile to many times more instructions. patterns are the sizes of the
// condition's patterns.
type costs struct{ patterns map[string]uint64 }

func (c costs) CallCost(function, _ string, args []ref.Val, _ ref.Val) *uint64 {
	n := uint64(1)
	switch function {
	case looping:
		// A loop over a map, as it starts, 1 for each of its keys, however few steps it takes, as
		// collecting them to order them reads each (stepping.inOrder): a loop over one inside
		// another would otherwise take time growing with the map's size and the outer loop's steps,
		// charged only for the steps.
		n = 0
		if len(args) > 0 {
			if m, ok := args[0].(traits.Mapper); ok {
				n = count(m)
			}
		}
	case operators.NotStrictlyFalse:
		// 1, as the condition of a step of all() or exists().
	case overloads.Matches:
		if len(args) != 2 {
			return nil
		}
		n = matchCost(args[0], c.size(args[1]))
	case overloads.Contains, overloads.StartsWith, overloads.EndsWith:
		n = searchCost(function, args)
	case operators.Equals, operators.NotEquals, operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals, operators.In:
		if len(args) != 2 {
			return nil
		}
		// 1, as what it reads is charged as bounded measures it, before it runs.
	case operators.Add, overloads.Size, overloads.TypeConvertInt, overloads.TypeConvertUint, overloads.TypeConvertDouble,
		overloads.TypeConvertBool, overloads.TypeConvertString, overloads.TypeConvertBytes,
		overloads.TypeConvertTimestamp, overloads.TypeConvertDuration:
		// These read strings and bytes whole, and lists and maps by their length.
		for _, v := range args {
			n += textSize(v)
		}
	default:
		if !timePart(function) || len(args) < 2 {
			return nil
		}
		n = zoneCost
	}
	return &n
}

// worst is what evaluating a checked condition can cost at most, as costs and CEL charge it when it
// runs: each node at the most it can, which the condition's literals and types bound, and past
// maxCost where it reads, or loops over, a value whose size the request decides, as an attribute
// does. It counts an identifier, a select and an index twice what CEL charges for one, as it can
// plan one as an attribute of its own.
type worst struct {
	costs
	checked *ast.AST
	// vars are what the comprehensions' variables in scope range over, by name; nil for what their
	// type bounds.
	vars map[string][]*extent
}

// extent is the most an expression's value can be: its valueSize and textSize, the elements of a
// list or the keys of a map, the bytes of a string, what each element or key can be, nil for no
// more than the value (inside), and whether it is a map when it runs.
type extent struct {
	value, text, length, bytes uint64
	elem                       *extent
	form                       form
}

// form is whether a value is a map when it runs, whatever CEL checks it as (typed): `in` finds a
// key in a map by reading the key, and in anything else reads what it searches. The zero form may
// be either.
type form uint8

const (
	// notMap is a list, a scalar, a string or bytes.
	notMap form = iota + 1
	// isMap is a map, as a map literal and a variable declared one are.
	isMap
)

// unbounded is a cost or a size a condition doesn't bound.
const unbounded = math.MaxUint64

var anything = extent{value: unbounded, text: unbounded, length: unbounded, bytes: unbounded}

// inside is the most a value inside one x bounds can be, as an element, a key or a field: no more
// than x, whose valueSize counts each of them whole.
func inside(x extent) extent {
	if x.value == unbounded {
		return anything
	}
	// A string's valueSize is a tenth of its bytes, and a list's or a map's at least its length.
	return extent{value: x.value, text: x.value, length: x.value, bytes: cost.SafeMultiply(x.value, 10)}
}

func (x extent) union(y extent) extent {
	u := extent{value: max(x.value, y.value), text: max(x.text, y.text), length: max(x.length, y.length), bytes: max(x.bytes, y.bytes)}
	if x.form == y.form {
		u.form = x.form
	}
	// A value of no elements, as the empty list map() and filter() start from, has none to bound.
	switch {
	case x.length == 0:
		u.elem = y.elem
	case y.length == 0:
		u.elem = x.elem
	case x.elem != nil && y.elem != nil:
		e := x.elem.union(*y.elem)
		u.elem = &e
	}
	return u
}

// worstCost is what evaluating checked can cost at most, no more than maxCost. It reads the macros
// as CEL expands them and the types it checks, so another version of CEL can bound a condition
// already stored otherwise (TestStoredConditionsKeepTheirBounds).
func worstCost(checked *cel.Ast, patterns map[string]uint64) uint64 {
	w := worst{costs: costs{patterns}, checked: checked.NativeRep(), vars: map[string][]*extent{}}
	n, _ := w.walk(w.checked.Expr())
	return min(n, maxCost)
}

func (w worst) walk(e ast.Expr) (uint64, extent) {
	switch e.Kind() {
	case ast.LiteralKind:
		v := e.AsLiteral()
		x := extent{value: valueSize(v, unbounded), text: textSize(v), form: notMap}
		switch v := v.(type) {
		case types.String:
			x.bytes = uint64(len(v))
		case types.Bytes:
			x.bytes = uint64(len(v))
		}
		return 0, x
	case ast.IdentKind:
		if xs := w.vars[e.AsIdent()]; len(xs) > 0 && xs[len(xs)-1] != nil {
			return 2, *xs[len(xs)-1]
		}
		if w.root(e, "action") {
			return 2, text(maxPermission)
		}
		return 2, w.typed(e)
	case ast.SelectKind:
		sel := e.AsSelect()
		n, x := w.walk(sel.Operand())
		// A presence test is a bool; a field may be what its type isn't (typed).
		if sel.IsTestOnly() {
			return cost.SafeAdd(n, 2), w.typed(e)
		}
		for v, fields := range named {
			if w.root(sel.Operand(), v) && slices.Contains(fields, sel.FieldName()) {
				return cost.SafeAdd(n, 2), text(MaxID)
			}
		}
		// The request's time is the timestamp a check passes (vars), though CEL checks it as anything
		// a map of dyn may hold, so adding to it or converting it was bounded as reading a value of
		// any size, at all a condition may cost.
		if w.root(sel.Operand(), "request") && sel.FieldName() == "time" {
			return cost.SafeAdd(n, 2), extent{value: 1, text: 1, form: notMap}
		}
		return cost.SafeAdd(n, 2), inside(x)
	case ast.ListKind:
		n, x := cost.SafeAdd(10, building(e)), extent{value: 1, text: 1, length: uint64(len(e.AsList().Elements())), form: notMap}
		for i, el := range e.AsList().Elements() {
			c, ex := w.walk(el)
			n, x.value = cost.SafeAdd(n, c), cost.SafeAdd(x.value, ex.value)
			if i == 0 {
				x.elem = &ex
			} else {
				u := x.elem.union(ex)
				x.elem = &u
			}
		}
		return n, x
	case ast.MapKind:
		n, x := cost.SafeAdd(30, building(e)), extent{value: 1, text: 1, length: uint64(len(e.AsMap().Entries())), form: isMap}
		for i, entry := range e.AsMap().Entries() {
			ck, k := w.walk(entry.AsMapEntry().Key())
			cv, v := w.walk(entry.AsMapEntry().Value())
			ck = cost.SafeAdd(ck, keyCost(entry.AsMapEntry().Key(), k))
			n, x.value = cost.SafeAdd(n, cost.SafeAdd(ck, cv)), cost.SafeAdd(x.value, cost.SafeAdd(k.value, v.value))
			if i == 0 {
				x.elem = &k
			} else {
				u := x.elem.union(k)
				x.elem = &u
			}
		}
		return n, x
	case ast.ComprehensionKind:
		return w.comprehension(e)
	case ast.CallKind:
		return w.call(e)
	default:
		return unbounded, anything
	}
}

// maxPermission is the longest a permission is, in bytes: `type:verb`, each a name of at most 63
// (permissionName), as the action a check passes is, once Authorize has refused one that isn't, and
// a role's are where they are stored.
const maxPermission = 127

// named are the fields of the subject and the resource a check passes of at most MaxID bytes, as
// it refuses a subject, a resource or its tenant otherwise (Authorizer.subject, Resource.validate):
// a kind's name and a type's are shorter still.
var named = map[string][]string{"subject": {"kind", "id"}, "resource": {"type", "id", "tenant"}}

// root reports whether e names the variable name a check passes, not a comprehension's variable of
// the same name, which CEL checks the variable as `.name` beside.
func (w worst) root(e ast.Expr, name string) bool {
	if e.Kind() != ast.IdentKind {
		return false
	}
	id := e.AsIdent()
	return id == "."+name || id == name && len(w.vars[name]) == 0
}

// text is the most a string of at most n bytes can be.
func text(n uint64) extent {
	size := 1 + n/10
	return extent{value: size, text: size, bytes: n, form: notMap}
}

// typed is the most a value of e's type can be: one for a scalar, and for a string, a list or a map
// past any bound. It is only for what can't be another type than CEL checks it as, as a variable, a
// function's result or a presence test: where a dyn() value meets another, in a choice, a sum or a
// literal, CEL checks it as of the other's type, and so what reads it, a field, an element or a
// loop's variable, whatever it is when it runs.
func (w worst) typed(e ast.Expr) extent {
	switch w.checked.GetType(e.ID()).Kind() {
	case types.BoolKind, types.IntKind, types.UintKind, types.DoubleKind, types.DurationKind, types.TimestampKind,
		types.NullTypeKind, types.TypeKind:
		return extent{value: 1, text: 1, form: notMap}
	case types.ListKind:
		x := anything
		x.text, x.form = 1, notMap
		return x
	case types.MapKind:
		x := anything
		x.text, x.form = 1, isMap
		return x
	default:
		return anything
	}
}

func (w worst) comprehension(e ast.Expr) (uint64, extent) {
	comp := e.AsComprehension()
	n, over := w.walk(comp.IterRange())
	init, start := w.walk(comp.AccuInit())
	// A macro making a list, as map() and filter() do, starts from an empty one, and each loop's step
	// adds to it what it would add to that: one element, transformed or as it is, which reads no
	// other, as no condition can name the list being made. CEL names it @result, which no
	// identifier can be: where it names it otherwise, as a version of it may, a step could read it
	// and grow it by more each loop.
	making := comp.AccuInit().Kind() == ast.ListKind && strings.HasPrefix(comp.AccuVar(), "@")
	var accu *extent
	if making {
		accu = &start
	}
	// Each element is what the range's bound says, or no more than the range, whatever CEL checks
	// it as (typed).
	each := over.elem
	if each == nil {
		in := inside(over)
		each = &in
	}
	w.vars[comp.IterVar()] = append(w.vars[comp.IterVar()], each)
	if comp.HasIterVar2() {
		a := anything
		w.vars[comp.IterVar2()] = append(w.vars[comp.IterVar2()], &a)
	}
	w.vars[comp.AccuVar()] = append(w.vars[comp.AccuVar()], accu)
	cond, _ := w.walk(comp.LoopCondition())
	step, once := w.walk(comp.LoopStep())
	x := w.typed(e)
	if making {
		x = grown(start, once, over.length)
		w.vars[comp.AccuVar()][len(w.vars[comp.AccuVar()])-1] = &x
	}
	result, _ := w.walk(comp.Result())
	for _, v := range []string{comp.IterVar(), comp.IterVar2(), comp.AccuVar()} {
		if xs := w.vars[v]; len(xs) > 0 && (v != comp.IterVar2() || comp.HasIterVar2()) {
			w.vars[v] = xs[:len(xs)-1]
		}
	}
	// Each element evaluates the condition, and the step while it holds; a map's keys are sorted
	// first (stepping.inOrder), each key, as each element bounds it, read once.
	loops := cost.SafeMultiply(over.length, cost.SafeAdd(cond, step))
	if over.form != notMap {
		n = cost.SafeAdd(n, sortCost(over.length, each.text))
	}
	return cost.SafeAdd(cost.SafeAdd(n, init), cost.SafeAdd(loops, result)), x
}

// grown is the most a list can be that starts as start and grows, each of n loops, by as much as
// once, a loop's step from start, grew it.
func grown(start, once extent, n uint64) extent {
	more := func(from, to uint64) uint64 { return cost.SafeAdd(from, cost.SafeMultiply(n, to-min(to, from))) }
	return extent{
		value: more(start.value, once.value), text: 1, length: more(start.length, once.length), elem: start.union(once).elem,
		form: notMap,
	}
}

func (w worst) call(e ast.Expr) (uint64, extent) {
	call := e.AsCall()
	args := call.Args()
	// A method's target is its first argument when it runs.
	if call.IsMemberFunction() {
		args = append([]ast.Expr{call.Target()}, args...)
	}
	var n uint64
	xs := make([]extent, len(args))
	for i, a := range args {
		var c uint64
		c, xs[i] = w.walk(a)
		n = cost.SafeAdd(n, c)
	}
	own, x := uint64(1), w.typed(e)
	switch fn := call.FunctionName(); fn {
	case operators.Conditional:
		// It, and a logical operator, costs 1 though CEL charges nothing, as a loop's step evaluating
		// it is charged 1 more (free).
		if len(xs) == 3 {
			x = xs[1].union(xs[2])
		}
	case "dyn":
		if len(xs) == 1 {
			x = xs[0]
		}
	case operators.Index:
		own, x = 2, anything
		if len(xs) == 2 {
			own = cost.SafeAdd(own, keyCost(args[1], xs[1]))
			// A map's elem bounds its keys, not what they index.
			x = inside(xs[0])
			if xs[0].elem != nil && xs[0].form == notMap {
				x = *xs[0].elem
			}
		}
	case overloads.Matches:
		own = unbounded
		if len(xs) == 2 && args[1].Kind() == ast.LiteralKind {
			own = cost.SafeMultiply(xs[0].text, w.size(args[1].AsLiteral()))
		}
	case operators.Equals, operators.NotEquals, operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals, operators.In:
		if len(xs) != 2 {
			return unbounded, x
		}
		// Finding x in a map reads x, and in anything else what it is found in.
		switch {
		case fn != operators.In:
			own = cost.SafeAdd(1, min(xs[0].value, xs[1].value))
		case xs[1].form == isMap:
			own = cost.SafeAdd(1, xs[0].value)
		case xs[1].form == notMap:
			own = cost.SafeAdd(1, xs[1].value)
		default:
			own = cost.SafeAdd(1, max(xs[0].value, xs[1].value))
		}
	case operators.Add, overloads.Size, overloads.TypeConvertInt, overloads.TypeConvertUint, overloads.TypeConvertDouble,
		overloads.TypeConvertBool, overloads.TypeConvertString, overloads.TypeConvertBytes,
		overloads.TypeConvertTimestamp, overloads.TypeConvertDuration:
		for _, a := range xs {
			own = cost.SafeAdd(own, a.text)
		}
		if fn == operators.Add && len(xs) == 2 {
			x = added(xs[0], xs[1])
		}
	case overloads.Contains:
		// As searchCost charges it.
		if len(xs) == 2 {
			own = cost.SafeMultiply(xs[0].text, xs[1].text)
		}
	case overloads.StartsWith, overloads.EndsWith:
		if len(xs) == 2 {
			own = min(xs[0].text, xs[1].text)
		}
	default:
		// Loading the zone, as inZone charges it, where no literal names it.
		if timePart(fn) && len(xs) >= 2 {
			own = zoneCost
			if !namedZone(args[1]) {
				own += zoneLoad
			}
		}
	}
	return cost.SafeAdd(n, own), x
}

// keyCost is what a map reading key, which x bounds, costs past what CEL charges, as keying
// charges it.
func keyCost(key ast.Expr, x extent) uint64 {
	if !computed(key) {
		return 0
	}
	return x.text - min(x.text, 1)
}

// added is the most what adding x and y makes can be, whatever their types, as CEL may check a sum
// as of another type than it is (typed): a list of both's elements, a string or bytes of both's, or
// a number or a time.
func added(x, y extent) extent {
	return extent{
		value: cost.SafeAdd(x.value, y.value), text: cost.SafeAdd(x.text, y.text),
		length: cost.SafeAdd(x.length, y.length), bytes: cost.SafeAdd(x.bytes, y.bytes), elem: x.union(y).elem,
		// CEL adds no maps.
		form: notMap,
	}
}

// searchCost is what searching a string for another costs, as contains, startsWith and endsWith
// do, at least 1 however short either is: CEL charges a tenth of the characters of what is searched
// for, and for contains of both, multiplied, rounded up, which is nothing where one is empty, though
// counting the characters copies the other whole. contains tries each place in one for the other,
// reading as much of both as it may at each, so it costs reading both, multiplied, and startsWith
// and endsWith try one, reading no more of either than the shorter holds. A value that isn't a
// string costs 1, as the call fails without reading it.
func searchCost(function string, args []ref.Val) uint64 {
	if len(args) != 2 {
		return 1
	}
	x, y := textSize(args[0]), textSize(args[1])
	if function == overloads.Contains {
		return cost.SafeMultiply(x, y)
	}
	return min(x, y)
}

// bounded refuses, before running it, a comparison or a search in a list that would read more than
// a condition may: one call reads it all, and a call's cost is counted only once it has run, so a
// list a condition doubles cheaply would otherwise hold a check for as long as walking it takes.
// It charges what a comparison reads as it measures it (measured), before the comparison runs,
// beside the steps (counting), so it reads the values once to measure them, however large, where
// measuring them again for CEL's charge, and again in search of a double that isn't finite, read
// them about ten times for each unit charged. It refuses a comparison of such a double too, or of
// attributes no condition reads (refusing), a time read in a zone that can't be one
// (inZone), and a search of a string that would cost more than a condition may (searched). It notes
// each call it plans so.
func (g *guards) bounded(i interpreter.Interpretable) (interpreter.Interpretable, error) {
	call, ok := i.(interpreter.InterpretableCall)
	if !ok || !guarded(call.Function(), len(call.Args())) {
		return i, nil
	}
	if g.ids[call.ID()] {
		g.planned[call.ID()] = true
	}
	if timePart(call.Function()) {
		return g.inZone(call)
	}
	if search := searchOf(call.Function()); search != nil {
		return searched(call, search), nil
	}
	// read is what comparing reads of the values.
	var op func(x, y ref.Val, read uint64) ref.Val
	switch call.Function() {
	case operators.Equals:
		op = equal
	case operators.NotEquals:
		op = func(x, y ref.Val, read uint64) ref.Val {
			eq := equal(x, y, read)
			if b, ok := eq.(types.Bool); ok {
				return !b
			}
			return eq
		}
	case operators.In:
		op = func(x, y ref.Val, _ uint64) ref.Val {
			if l, ok := y.(traits.Lister); ok {
				return contains(l, x)
			}
			if c, ok := y.(traits.Container); ok {
				return c.Contains(x)
			}
			return types.NoSuchOverloadErr()
		}
	case operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals:
		order := ordering(call.Function())
		op = func(x, y ref.Val, _ uint64) ref.Val { return order(x, y) }
	default:
		return i, nil
	}
	function, limit := call.Function(), g.limit
	return &charged{InterpretableCall: call, run: func(vars interpreter.Activation, args []ref.Val) ref.Val {
		if len(args) != 2 {
			return types.NoSuchOverloadErr()
		}
		n, failed := measured(function, args[0], args[1])
		// Past what a condition may cost, this cancels the evaluation, which then costs its limit.
		chargePast(vars, n, limit)
		if n > maxCost {
			return types.NewErr("rbac: comparing values this large costs more than a condition may")
		}
		if failed != nil {
			return failed
		}
		return op(args[0], args[1], n)
	}}, nil
}

// charged is a call bounded plans, run on what the condition evaluating it reads, so it can charge
// what it reads before it runs (chargePast), as CEL charges a call only once it has run. Once it has
// run, it charges CEL's tracking as the call it is, as each call CEL plans charges itself as it
// runs: the call it is planned in place of never runs, and left so, a comparison cost 1 less, and
// reading a time in a zone zoneCost less, than the bound counts.
type charged struct {
	interpreter.InterpretableCall
	run func(vars interpreter.Activation, args []ref.Val) ref.Val
}

// Exec evaluates the arguments as CEL runs a call, a failing one failing it before the rest.
func (c *charged) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	planned := c.Args()
	args := make([]ref.Val, len(planned))
	for i, a := range planned {
		if args[i] = a.Exec(frame); types.IsUnknownOrError(args[i]) {
			return args[i]
		}
	}
	out := types.LabelErrNode(c.ID(), c.run(frame, args))
	if costs := frame.CostTracker(); costs != nil {
		costs.EvalVarArgs(frame, c.ID(), c, args, out)
	}
	return out
}

func (c *charged) Eval(vars interpreter.Activation) ref.Val {
	return interpreter.EvalActivation(vars, c.Exec)
}

// guarded reports whether bounded plans a call of function with args arguments to fail before it
// runs: a comparison, a search of a list or a string, or reading a part of a time in a zone.
func guarded(function string, args int) bool {
	switch function {
	case operators.Equals, operators.NotEquals, operators.Less, operators.LessEquals, operators.Greater, operators.GreaterEquals,
		operators.In:
		return true
	}
	return searchOf(function) != nil || timePart(function) && args == 2
}

// guards are the ids of the calls checked holds that bounded or matching refuses before they run,
// and planned those each planned so: another version of CEL may plan one where neither sees it, as
// a call by another name, which would run whole before it is charged, however long, or compare a
// double that isn't finite as CEL does, so plan refuses it, as it refuses a loop it can't bound.
// literalZones are those of the calls reading a time in a zone a literal names, which worst charges
// no load of (inZone), and limit is the condition's, which what bounded charges takes it past, as a
// step does.
type guards struct {
	ids, planned, literalZones map[int64]bool
	limit                      uint64
}

func newGuards(checked *ast.AST, limit uint64) *guards {
	g := &guards{ids: map[int64]bool{}, planned: map[int64]bool{}, literalZones: map[int64]bool{}, limit: limit}
	for _, e := range ast.MatchDescendants(ast.NavigateAST(checked), ast.KindMatcher(ast.CallKind)) {
		call := e.AsCall()
		// A method's target is its first argument when it runs.
		args := call.Args()
		if call.IsMemberFunction() {
			args = append([]ast.Expr{call.Target()}, args...)
		}
		if guarded(call.FunctionName(), len(args)) || call.FunctionName() == overloads.Matches {
			g.ids[e.ID()] = true
		}
		if timePart(call.FunctionName()) && len(args) == 2 && namedZone(args[1]) {
			g.literalZones[e.ID()] = true
		}
	}
	return g
}

// namedZone reports whether e, the zone a time is read in, is a string literal, which a condition is
// planned with the zone it names loaded (inZone).
func namedZone(e ast.Expr) bool {
	if e.Kind() != ast.LiteralKind {
		return false
	}
	_, ok := e.AsLiteral().(types.String)
	return ok
}

// zone is a time zone a condition reads times in, loaded, or why its name names none.
type zone struct {
	loc *time.Location
	err error
}

// zones are the time zones conditions read times in, by name, each loaded once for the process, and
// so the names that name none too: CEL loads a zone from the platform's files each time it reads a
// time in one, which took ten microseconds for a zone and thirty for a name of none, and for a name
// of a file there that isn't one, as tzdata.zi, it read the file's 107 KB, failed to parse it and
// searched the other places, over a hundred microseconds, each charged zoneCost. Bounded, as
// requests name them: past maxZones, one kept is dropped at random for the next, as a program is
// (conditions.compile). A zone the platform's files change after the process loaded it reads as it
// was until the process drops it, as the zone the process runs in does.
var zones = struct {
	sync.RWMutex
	byName map[string]zone
}{byName: map[string]zone{}}

// keptZone is the zone named, and whether the process has loaded it.
func keptZone(name string) (zone, bool) {
	zones.RLock()
	defer zones.RUnlock()
	z, ok := zones.byName[name]
	return z, ok
}

// loadZone loads the zone named, or finds it names none, and keeps what it found, but where the
// platform's files failed to give it for a while (settled).
func loadZone(name string) zone {
	loadingZone()
	var z zone
	z.loc, z.err = locating(name)
	if !settled(z.err) {
		return z
	}
	zones.Lock()
	defer zones.Unlock()
	for k := range zones.byName {
		if len(zones.byName) < maxZones {
			break
		}
		delete(zones.byName, k)
	}
	zones.byName[name] = z
	return z
}

// settled reports whether loading a zone that failed with err would fail again, as for a name of no
// zone, of a file that isn't one or of a directory: not where reading the platform's files failed,
// as once the process has run out of file descriptors, which kept would fail a real zone for the
// process until it was dropped.
func settled(err error) bool {
	var errno syscall.Errno
	return err == nil || !errors.As(err, &errno) || errno == syscall.EISDIR || errno == syscall.ENOTDIR
}

// locating loads a time zone from the platform's files, as a test's stand-in for them.
var locating = time.LoadLocation

// zoneName refuses a name of no zone, before one is loaded: one of more than maxZone bytes, which
// loading copies for each place it looks; one holding a byte other than a letter, a digit, '/', '_',
// '-' or '+', as no name in the time zone database does, so no other file kept beside them, as
// tzdata.zi, is read as one; and one of Local, the zone the process runs in, by which a condition
// would decide by where each replica runs, or localtime, which some platforms keep beside the zones
// as a link to that zone, as a part of it, in any case: those keeping posix as a link to the zones'
// own directory loaded the process's zone as posix/localtime, and a file system ignoring case would
// as LocalTime. No zone's name holds either.
func zoneName(name string) error {
	if len(name) > maxZone {
		return fmt.Errorf("rbac: a time zone is at most %d bytes", maxZone)
	}
	for part := range strings.SplitSeq(name, "/") {
		if strings.EqualFold(part, "Local") || strings.EqualFold(part, "localtime") {
			return errors.New("rbac: a time zone is named, not the one the process runs in")
		}
	}
	for i := range len(name) {
		switch b := name[i]; {
		case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9', b == '/', b == '_', b == '-', b == '+':
		default:
			return fmt.Errorf("rbac: %q names no time zone", name)
		}
	}
	return nil
}

// inZone is call, reading a part of a time in a zone, as CEL reads it, but for loading each zone
// once for the process (zones), and refusing a name of none before loading anything (zoneName).
// Reading a time in a zone an attribute names costs zoneLoad past what CEL charges, before it loads
// (chargePast), as a zone a request passes can be a new one each time, whether or not the process
// has loaded it: charged only where it hadn't, the same check of the same request was refused the
// first time and allowed after, and decided by which zones each replica had loaded, as Authorize
// and Explain did one after the other. The zone a literal names is loaded, or found to be none,
// when the condition is planned, as matching compiles a pattern, so evaluating it loads nothing
// however many zones the process has dropped since, and worst charges it no load; one CEL plans
// otherwise, as another version may, isn't a condition, and one the platform's files fail to give
// while it is planned isn't planned, so a check plans it again. A fixed offset, as "+05:30", CEL
// reads without loading anything.
func (g *guards) inZone(call interpreter.InterpretableCall) (interpreter.InterpretableCall, error) {
	var planned *zone
	if args := call.Args(); g.literalZones[call.ID()] && len(args) == 2 {
		c, ok := args[1].(interpreter.InterpretableConst)
		if !ok {
			return nil, errors.New("a time zone a literal names is planned where this package can't load it once")
		}
		if name, ok := c.Value().(types.String); ok && !strings.Contains(string(name), ":") && zoneName(string(name)) == nil {
			z, kept := keptZone(string(name))
			if !kept {
				z = loadZone(string(name))
			}
			// Planned with the failure, it would fail for as long as checks keep the program.
			if !settled(z.err) {
				return nil, fmt.Errorf("loading the time zone %q: %w", name, z.err)
			}
			planned = &z
		}
	}
	function, overload, limit := call.Function(), call.OverloadID(), g.limit
	return &charged{InterpretableCall: call, run: func(vars interpreter.Activation, args []ref.Val) ref.Val {
		if len(args) != 2 {
			return types.NoSuchOverloadErr()
		}
		name, ok := args[1].(types.String)
		if !ok {
			return types.MaybeNoSuchOverloadErr(args[1])
		}
		if len(name) > maxZone {
			return types.NewErr("rbac: a time zone is at most %d bytes", maxZone)
		}
		t, ok := args[0].(types.Timestamp)
		if !ok {
			return types.MaybeNoSuchOverloadErr(args[0])
		}
		if strings.Contains(string(name), ":") {
			return t.Receive(function, overload, args[1:])
		}
		z := planned
		if z == nil {
			if err := zoneName(string(name)); err != nil {
				return types.WrapErr(err)
			}
			chargePast(vars, zoneLoad, limit)
			found, kept := keptZone(string(name))
			if !kept {
				found = loadZone(string(name))
			}
			z = &found
		}
		if z.err != nil {
			return types.WrapErr(z.err)
		}
		// Read as CEL reads a time with no zone, in the time's own, so the zone isn't loaded again.
		return types.Timestamp{Time: t.In(z.loc)}.Receive(function, "", nil)
	}}, nil
}

// searchOf is what CEL binds function to where it searches a string, or nil where it doesn't.
func searchOf(function string) func(s, sub ref.Val) ref.Val {
	switch function {
	case overloads.Contains:
		return types.StringContains
	case overloads.StartsWith:
		return types.StringStartsWith
	case overloads.EndsWith:
		return types.StringEndsWith
	}
	return nil
}

// searched is call, a search of a string as search, which CEL binds it to, failing before it runs
// where it would cost more than a condition may (searchCost): a search's cost is counted only once
// it has run, and contains of a string the request passes in another, each of a mebibyte or less,
// can try each place in it reading most of what it searches for, which took a third of a second.
func searched(call interpreter.InterpretableCall, search func(s, sub ref.Val) ref.Val) interpreter.InterpretableCall {
	function := call.Function()
	return interpreter.NewCall(call.ID(), function, call.OverloadID(), call.Args(), func(args ...ref.Val) ref.Val {
		if len(args) != 2 {
			return types.NoSuchOverloadErr()
		}
		if searchCost(function, args) > maxCost {
			return types.NewErr("rbac: searching strings this long costs more than a condition may")
		}
		searching()
		return search(args[0], args[1])
	})
}

// stringing converts a value to a string as CEL does, failing for a double that isn't finite, as
// int() and uint() of one do: "NaN" compares as any string does, so a deny's
// `string(failed / total) == "0.5"` would lift where both are 0.0. It holds the environment's own
// overloads of string(), each by its id and, by the function's name, the one choosing among them by
// a value's type, and runs the one a program would: CEL picks one by the type it checked, which a
// value it checks as of another's type, as `(dyn([true]) + [""])[0]`, needn't have. It reads them
// once a program converts a value to a string: reading them copies every function the environment
// declares, which takes about a tenth as long as planning a short condition.
type stringing struct {
	env       *cel.Env
	overloads map[string]*functions.Overload
}

func (s *stringing) decorate(i interpreter.Interpretable) (interpreter.Interpretable, error) {
	call, ok := i.(interpreter.InterpretableCall)
	if !ok || call.Function() != overloads.TypeConvertString {
		return i, nil
	}
	if s.overloads == nil {
		s.overloads = map[string]*functions.Overload{}
		if fn, ok := s.env.Functions()[overloads.TypeConvertString]; ok {
			bindings, err := fn.Bindings()
			if err != nil {
				return nil, err
			}
			for _, o := range bindings {
				s.overloads[o.Operator] = o
			}
		}
	}
	impl := s.overloads[call.OverloadID()]
	if impl == nil {
		impl = s.overloads[call.Function()]
	}
	// Another version of CEL may bind it otherwise, which this can't run as CEL would.
	if impl == nil || impl.Unary == nil && impl.Function == nil {
		return nil, errors.New("a conversion to a string is planned where this package can't check it")
	}
	return interpreter.NewCall(call.ID(), call.Function(), call.OverloadID(), call.Args(), func(args ...ref.Val) ref.Val {
		if len(args) != 1 {
			return types.NoSuchOverloadErr()
		}
		if nonFinite(args[0]) {
			return types.NewErr("rbac: a double that isn't finite can't be converted to a string")
		}
		if impl.Unary != nil {
			return impl.Unary(args[0])
		}
		return impl.Function(args...)
	}), nil
}

// timePart reports whether function reads a part of a time, in a zone where it is given one.
func timePart(function string) bool {
	switch function {
	case overloads.TimeGetFullYear, overloads.TimeGetMonth, overloads.TimeGetDayOfYear, overloads.TimeGetDate,
		overloads.TimeGetDayOfMonth, overloads.TimeGetDayOfWeek, overloads.TimeGetHours, overloads.TimeGetMinutes,
		overloads.TimeGetSeconds, overloads.TimeGetMilliseconds:
		return true
	}
	return false
}

// looping is what costs charges a loop over a map as when it starts (stepping.inOrder).
const looping = "@looping"

// stepping plans each of checked's loops' conditions as a step, which a loop evaluates first at each
// of its steps: it counts the steps, each costing at least 1, and charges each 1 more for each
// logical operator and choice it may evaluate (free), which limit bounds (counting). A loop's range
// it plans to give a map's keys in one order, charging each key as the loop starts (order).
type stepping struct {
	// ranges are the ids of the ranges of checked's loops, by those of their conditions, and stepped
	// those of the conditions planned as steps. operators are what each of a loop's steps may
	// evaluate (free), by its condition's id. over are the ranges' ids, lists those CEL checks as
	// lists, and ordered those order planned.
	ranges                        map[int64]int64
	over, stepped, lists, ordered map[int64]bool
	operators                     map[int64]uint64
	limit                         uint64
}

func newStepping(checked *ast.AST, limit uint64) *stepping {
	s := &stepping{
		ranges: map[int64]int64{}, over: map[int64]bool{}, stepped: map[int64]bool{}, lists: map[int64]bool{},
		ordered: map[int64]bool{}, operators: map[int64]uint64{}, limit: limit,
	}
	for _, e := range ast.MatchDescendants(ast.NavigateAST(checked), ast.KindMatcher(ast.ComprehensionKind)) {
		comp := e.AsComprehension()
		s.ranges[comp.LoopCondition().ID()] = comp.IterRange().ID()
		s.over[comp.IterRange().ID()] = true
		s.lists[comp.IterRange().ID()] = checked.GetType(comp.IterRange().ID()).Kind() == types.ListKind
		s.operators[comp.LoopCondition().ID()] = free(comp.LoopCondition()) + free(comp.LoopStep())
	}
	return s
}

// free is how many logical operators and choices e evaluates at most, but for those of the steps of
// the loops it holds, which theirs count: CEL charges one nothing, nor the literal it may read, though
// evaluating one takes about as long as a unit of cost does, so a loop whose steps evaluated hundreds
// took twenty times what it was charged. A step costs 1 more for each, on top of what CEL charges it,
// however much that is, and the bound counts them alike.
func free(e ast.Expr) uint64 {
	var n uint64
	switch e.Kind() {
	case ast.CallKind:
		call := e.AsCall()
		switch call.FunctionName() {
		case operators.LogicalAnd, operators.LogicalOr, operators.Conditional:
			n++
		}
		if call.IsMemberFunction() {
			n += free(call.Target())
		}
		for _, a := range call.Args() {
			n += free(a)
		}
	case ast.SelectKind:
		n += free(e.AsSelect().Operand())
	case ast.ListKind:
		for _, el := range e.AsList().Elements() {
			n += free(el)
		}
	case ast.MapKind:
		for _, entry := range e.AsMap().Entries() {
			n += free(entry.AsMapEntry().Key()) + free(entry.AsMapEntry().Value())
		}
	case ast.ComprehensionKind:
		comp := e.AsComprehension()
		n += free(comp.IterRange()) + free(comp.AccuInit()) + free(comp.Result())
	default:
		// An identifier or a literal holds none.
	}
	return n
}

func (s *stepping) decorate(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
	if _, ok := s.ranges[i.ID()]; !ok {
		return i, nil
	}
	switch cond := i.(type) {
	case interpreter.InterpretableConst:
	case interpreter.InterpretableCall:
		// The macros' other condition, which CEL charges 1 whatever its arguments.
		if cond.Function() != operators.NotStrictlyFalse {
			return nil, fmt.Errorf("a loop's condition is planned as %s, which this package doesn't bound", cond.Function())
		}
	default:
		// Another version of CEL may plan a loop otherwise, which would run unbounded.
		return nil, fmt.Errorf("a loop's condition is planned as %T, which this package doesn't bound", i)
	}
	s.stepped[i.ID()] = true
	return &step{InterpretableV2: i, operators: s.operators[i.ID()], limit: s.limit}, nil
}

// step is a loop's condition as stepping plans it, which CEL evaluates, and charges, as it planned it.
type step struct {
	interpreter.InterpretableV2
	// operators are what each step may evaluate that CEL charges nothing (free), and limit the
	// condition's, which its loops' steps and what it was charged past CEL together may not pass.
	operators, limit uint64
}

func (s *step) Eval(a interpreter.Activation) ref.Val { return interpreter.EvalActivation(a, s.Exec) }

// Exec counts the step, charges its operators past what CEL charges, and cancels the evaluation past
// its limit, as CEL cancels one costing more. The keys and literals charged count too: a loop after
// them would take a limit of steps more, past it already. CEL charges the operators nothing, so they
// cost on top of what it charges: counted only toward the least a step costs, they ran uncharged in
// a step whose other work CEL charges more.
func (s *step) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	c, _ := frame.ResolveName(stepsName)
	n, ok := c.(*counting)
	if ok {
		n.steps++
		n.charged = cost.SafeAdd(n.charged, s.operators)
	}
	if !ok || cost.SafeAdd(n.steps, n.charged) > s.limit {
		panic(interpreter.EvalCancelledError{Cause: interpreter.CostLimitExceeded, Message: "rbac: a condition's loops take more steps than it may cost"})
	}
	return s.InterpretableV2.Exec(frame)
}

// order plans each of checked's loops' ranges to give a map's keys in one order (inOrder), not as
// Go ranges over the map, which changes from one evaluation to the next: a loop reads its keys in
// turn, so what map() and filter() made of them, and how far a loop went before it stopped, and so
// what it cost, turned on that order. Over a map of three keys,
// `request.attributes.scopes.map(k, k)[0] == "read"` held in 55 of 100 identical checks, Explain
// disagreeing with the check before it in 51, and a deny's
// `request.attributes.scopes.filter(k, true)[0] == "admin"` lifted in 84, so a requester could ask
// until it lifted. A range is planned as CEL planned it, of the same kind, and evaluated by what CEL
// planned, so CEL charges it as it would. One CEL plans as something else, as a loop, it leaves where
// CEL checks it as a list, and plan refuses otherwise.
func (s *stepping) order(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
	if !s.over[i.ID()] {
		return i, nil
	}
	switch r := i.(type) {
	case interpreter.InterpretableAttribute:
		i = &orderedAttribute{InterpretableAttribute: r, s: s}
	case interpreter.InterpretableConstructor:
		i = &orderedConstructor{InterpretableConstructor: r, s: s}
	case interpreter.InterpretableCall:
		i = &orderedCall{InterpretableCall: r, s: s}
	default:
		if !s.lists[i.ID()] {
			return i, nil
		}
	}
	s.ordered[i.ID()] = true
	return i, nil
}

// inOrder is v, the value of the loop's range id, giving its keys in one order where it is a map of
// more than one: sorted (sortKeys), once the condition evaluating on frame is charged what sorting
// them costs, before any is sorted, as worst bounds it (sortCost). That is 1 for each two keys at
// each of sortLevels, as comparing and moving a key took 13 to 15 ns, where a unit charged covers
// 20 to 145 ns of what the package does elsewhere, and what reading each key costs past 1
// (textSize), once: a comparison reads no more of a key than it holds, at about 50 bytes a
// nanosecond, so the eleven levels a condition can pay for read its bytes in a tenth of the time
// charging them once covers. Charged 1 for each key and what reading it costs at each level,
// sorting 500 keys of 36 bytes, as ids, cost 18,000, past what a condition may, for 64 µs of work,
// and 500 short keys, which a loop costing about half what a condition may reads, 4,500, for 57 µs.
// CEL's tracking is charged 1 for each key first, as the loop starts (costs), whatever their number.
// A map keyed by another type than keyRank orders, as a map literal keyed by lists can be, has no
// order, and a loop over it fails.
func (s *stepping) inOrder(frame *interpreter.ExecutionFrame, id int64, v ref.Val) ref.Val {
	if types.IsUnknownOrError(v) {
		return v
	}
	// CEL loops over a value that is a list or a map in Go whatever type it says it is, so one that
	// says it can't be looped over, as attributes no condition reads (refusing), is refused here:
	// looped over, `subject.attributes.all(k, false)` held where they were empty, and
	// `dyn(request.attributes).exists(k, k == "mfa_at")` where mfa_at was declared and passed as
	// another type, its key found.
	if !v.Type().HasTrait(traits.IterableType) {
		return types.LabelErrNode(id, types.NewErr("rbac: a value of type %s can't be looped over", v.Type().TypeName()))
	}
	m, ok := v.(traits.Mapper)
	if !ok {
		return v
	}
	if costs := frame.CostTracker(); costs != nil {
		costs.EvalUnary(frame, id, loopStart{}, m, nil)
	}
	n := count(m)
	if n < 2 {
		return v
	}
	// Charged before any key is read.
	chargePast(frame, sortSteps(n), s.limit)
	keys := make([]ref.Val, 0, n)
	if native := entries(m); native != nil {
		for k := range native {
			keys = append(keys, k)
		}
	} else {
		for it := m.Iterator(); it.HasNext() == types.True; {
			keys = append(keys, it.Next())
		}
	}
	var text uint64
	for _, k := range keys {
		if keyRank(k) < 0 {
			return types.LabelErrNode(id, types.NewErr("rbac: a map keyed by %s has no order to loop over it in", k.Type().TypeName()))
		}
		text += textSize(k) - 1
	}
	chargePast(frame, text, s.limit)
	return orderedMap{Mapper: m, keys: types.NewRefValList(types.DefaultTypeAdapter, sortKeys(keys))}
}

// loopStart is a loop over a map starting, as CEL's tracking charges it (costs).
type loopStart struct{}

func (loopStart) Function() string   { return looping }
func (loopStart) OverloadID() string { return "" }

// orderedMap is a map whose keys a loop gives in the order keys holds them. CEL loops over a map
// that folds itself by folding it, as Go ranges over it, and over any other by its iterator, so it
// has no Fold of its own: the map it embeds has one, which embedded as a traits.Mapper it hides.
type orderedMap struct {
	traits.Mapper
	keys traits.Lister
}

func (m orderedMap) Iterator() traits.Iterator { return m.keys.Iterator() }

// orderedAttribute is a loop's range CEL plans as an attribute, as a select or an index, ordered
// once resolved.
type orderedAttribute struct {
	interpreter.InterpretableAttribute
	s *stepping
}

func (a *orderedAttribute) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	return a.s.inOrder(frame, a.ID(), a.InterpretableAttribute.Exec(frame))
}

func (a *orderedAttribute) Eval(vars interpreter.Activation) ref.Val {
	return interpreter.EvalActivation(vars, a.Exec)
}

// orderedConstructor is a loop's range CEL plans as a literal, ordered once built.
type orderedConstructor struct {
	interpreter.InterpretableConstructor
	s *stepping
}

func (c *orderedConstructor) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	return c.s.inOrder(frame, c.ID(), c.InterpretableConstructor.Exec(frame))
}

func (c *orderedConstructor) Eval(vars interpreter.Activation) ref.Val {
	return interpreter.EvalActivation(vars, c.Exec)
}

// orderedCall is a loop's range CEL plans as a call, as dyn(), ordered once it has run.
type orderedCall struct {
	interpreter.InterpretableCall
	s *stepping
}

func (c *orderedCall) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	return c.s.inOrder(frame, c.ID(), c.InterpretableCall.Exec(frame))
}

func (c *orderedCall) Eval(vars interpreter.Activation) ref.Val {
	return interpreter.EvalActivation(vars, c.Exec)
}

// keyRank is where keys of v's type come in a loop over a map: bools, ints, uints, doubles, strings
// and then bytes, each type in its own order (compareKeys), or -1 for another type, which has none.
func keyRank(v ref.Val) int {
	switch v.(type) {
	case types.Bool:
		return 0
	case types.Int:
		return 1
	case types.Uint:
		return 2
	case types.Double:
		return 3
	case types.String:
		return 4
	case types.Bytes:
		return 5
	}
	return -1
}

// compareKeys orders x and y, of types keyRank orders: false before true, numbers by their values,
// and strings and bytes by their bytes. No two keys of a map compare equal: a map holds no NaN, and
// 0.0 and -0.0 are one key (comparableKey, misheld).
func compareKeys(x, y ref.Val) int {
	if c := cmp.Compare(keyRank(x), keyRank(y)); c != 0 {
		return c
	}
	switch x := x.(type) {
	case types.Bool:
		y, _ := y.(types.Bool)
		switch {
		case x == y:
			return 0
		case !bool(x):
			return -1
		}
		return 1
	case types.Int:
		y, _ := y.(types.Int)
		return cmp.Compare(x, y)
	case types.Uint:
		y, _ := y.(types.Uint)
		return cmp.Compare(x, y)
	case types.Double:
		y, _ := y.(types.Double)
		return cmp.Compare(x, y)
	case types.String:
		y, _ := y.(types.String)
		return strings.Compare(string(x), string(y))
	case types.Bytes:
		y, _ := y.(types.Bytes)
		return bytes.Compare(x, y)
	}
	return 0
}

// sortKeys sorts keys by compareKeys, merging runs that double in length, so it compares each key
// at most once at each of sortLevels(len(keys)) levels, as the run it is merged into: a comparison
// reads no more of either key than the shorter holds, so no more than of the key it places.
func sortKeys(keys []ref.Val) []ref.Val {
	buf := make([]ref.Val, len(keys))
	for width := 1; width < len(keys); width *= 2 {
		for lo := 0; lo < len(keys); lo += 2 * width {
			mid, hi := min(lo+width, len(keys)), min(lo+2*width, len(keys))
			i, j, k := lo, mid, lo
			for ; i < mid && j < hi; k++ {
				if compareKeys(keys[j], keys[i]) < 0 {
					buf[k], j = keys[j], j+1
				} else {
					buf[k], i = keys[i], i+1
				}
			}
			k += copy(buf[k:], keys[i:mid])
			copy(buf[k:], keys[j:hi])
		}
		keys, buf = buf, keys
	}
	return keys
}

// sortLevels is how many levels sortKeys merges n keys in: how many times n halves to 1.
func sortLevels(n uint64) uint64 {
	if n < 2 {
		return 0
	}
	return length(bits.Len64(n - 1))
}

// sortSteps is what comparing and moving n keys costs as sortKeys sorts them: 1 for each two at
// each level (stepping.inOrder).
func sortSteps(n uint64) uint64 { return cost.SafeMultiply(n/2+n%2, sortLevels(n)) }

// sortCost is the most ordering a map's keys costs (stepping.inOrder), where it holds at most n of
// them, each costing to read no more than text: sortSteps, and the rest of reading each once.
func sortCost(n, text uint64) uint64 {
	return cost.SafeAdd(sortSteps(n), cost.SafeMultiply(n, text-min(text, 1)))
}

// counting is what a condition reads, and how many steps its loops have taken, which it costs at
// least: CEL charges a step only what it evaluates, which can be nothing, as for a step reading
// only literals, so a loop over a long list the host passes would cost nothing for each element.
// charged is what the keys it computes, the literals it builds and the logical operators its loops'
// steps evaluate cost past what CEL charges (keying, literals, stepping), on top of the rest.
type counting struct {
	vars           map[string]any
	steps, charged uint64
}

// stepsName is what a condition's steps find their count by, which no condition can name, as no
// identifier starts with @.
const stepsName = "@steps"

func (c *counting) ResolveName(name string) (any, bool) {
	if name == stepsName {
		return c, true
	}
	v, ok := c.vars[name]
	return v, ok
}

func (*counting) Parent() interpreter.Activation { return nil }

// keying charges a map reading a key a condition computes, as looking one up or making a map
// literal of it does, by its length: the map hashes it whole, which CEL charges as 1 however long
// it is, so a loop looking up a long string the host passes would take time growing with its
// length, charged only for the steps. Each costs a tenth of its bytes more, as reading it does
// (textSize), counted beside the steps (counting). A double that isn't finite, or attributes no
// condition reads, fail as a key (comparableKey).
type keying struct {
	// keys are the ids of the keys checked computes, and planned what CEL planned each as last,
	// which is what it reads: it plans an index whose key isn't an attribute as an attribute under
	// the index's id before the index, so the key of an index that is itself a key is planned
	// twice under its id.
	keys    map[int64]bool
	planned map[int64]interpreter.InterpretableV2
	// fac qualifies a map by a key, as CEL's own attributes do.
	fac   interpreter.AttributeFactory
	limit uint64
}

func newKeying(env *cel.Env, checked *ast.AST, limit uint64) *keying {
	k := &keying{
		keys: map[int64]bool{}, planned: map[int64]interpreter.InterpretableV2{}, limit: limit,
		fac: interpreter.NewAttributeFactory(env.Container, env.CELTypeAdapter(), env.CELTypeProvider()),
	}
	key := func(e ast.Expr) {
		if computed(e) {
			k.keys[e.ID()] = true
		}
	}
	index := ast.FunctionMatcher(operators.Index)
	for _, e := range ast.MatchDescendants(ast.NavigateAST(checked), func(e ast.NavigableExpr) bool {
		return e.Kind() == ast.MapKind || index(e)
	}) {
		if e.Kind() == ast.MapKind {
			for _, entry := range e.AsMap().Entries() {
				key(entry.AsMapEntry().Key())
			}
		} else if args := e.AsCall().Args(); len(args) == 2 {
			key(args[1])
		}
	}
	return k
}

// computed reports whether key may be a string a condition doesn't spell out: not a literal, no
// longer than the condition, nor a list, a map, a test, a loop or a logical operator, none of
// which is a string.
func computed(key ast.Expr) bool {
	switch key.Kind() {
	case ast.LiteralKind, ast.ListKind, ast.MapKind, ast.ComprehensionKind:
		return false
	case ast.SelectKind:
		return !key.AsSelect().IsTestOnly()
	case ast.CallKind:
		fn := key.AsCall().FunctionName()
		return fn != operators.LogicalAnd && fn != operators.LogicalOr
	default:
		return true
	}
}

func (k *keying) decorate(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
	if !k.keys[i.ID()] {
		return i, nil
	}
	planned := i
	switch i := i.(type) {
	case interpreter.InterpretableConst:
		// Another version of CEL may fold a key, as `0.0 / 0.0`, which comparableKey wouldn't see.
		if nonFinite(i.Value()) {
			return nil, errors.New("a key is a double that isn't finite")
		}
	case interpreter.InterpretableAttribute:
		planned = &keyedAttribute{InterpretableAttribute: i, k: k}
	case interpreter.InterpretableCall:
		planned = &keyedCall{InterpretableCall: i, k: k}
	default:
		// Another version of CEL may plan a key otherwise, which would run uncharged: plan refuses
		// one not planned.
		delete(k.planned, i.ID())
		return i, nil
	}
	k.planned[i.ID()] = planned
	return planned, nil
}

// charge charges key, which planned evaluated, before a map reads it.
func (k *keying) charge(vars interpreter.Activation, planned interpreter.InterpretableV2, key any) {
	if k.planned[planned.ID()] != planned {
		return
	}
	var n uint64
	switch key := key.(type) {
	case string:
		n = uint64(len(key)) / 10
	case types.String:
		n = uint64(len(key)) / 10
	}
	if n > 0 {
		chargePast(vars, n, k.limit)
	}
}

// chargePast charges the condition evaluating on vars n past what CEL charges it (counting), and
// cancels the evaluation once its steps and what it was so charged cost more than limit, as CEL
// cancels one costing more.
func chargePast(vars interpreter.Activation, n, limit uint64) {
	c, _ := vars.ResolveName(stepsName)
	counted, ok := c.(*counting)
	if ok {
		counted.charged = cost.SafeAdd(counted.charged, n)
	}
	if !ok || cost.SafeAdd(counted.steps, counted.charged) > limit {
		panic(interpreter.EvalCancelledError{Cause: interpreter.CostLimitExceeded, Message: "rbac: what a condition reads, its keys and its literals cost more than it may"})
	}
}

// building is what a list or map literal costs past what CEL charges it, a constant however many
// it holds: 1 for each element it builds, and 2 for each entry, which the map hashes too, so a loop
// rebuilding a literal of hundreds at each step costs what it takes.
func building(e ast.Expr) uint64 {
	switch e.Kind() {
	case ast.ListKind:
		return uint64(len(e.AsList().Elements()))
	case ast.MapKind:
		return 2 * uint64(len(e.AsMap().Entries()))
	default:
		return 0
	}
}

// literals charges each list and map literal of a condition what building it costs, before it is
// built, beside the steps (counting), as keying charges a key. sizes are what each that holds any
// costs, by its id, named the entries each map literal names, and planned those planned so.
type literals struct {
	sizes   map[int64]uint64
	named   map[int64]int
	planned map[int64]bool
	limit   uint64
}

func newLiterals(checked *ast.AST, limit uint64) *literals {
	l := &literals{sizes: map[int64]uint64{}, named: map[int64]int{}, planned: map[int64]bool{}, limit: limit}
	for _, e := range ast.MatchDescendants(ast.NavigateAST(checked), func(e ast.NavigableExpr) bool {
		return e.Kind() == ast.ListKind || e.Kind() == ast.MapKind
	}) {
		if n := building(e); n > 0 {
			l.sizes[e.ID()] = n
		}
		if e.Kind() == ast.MapKind {
			l.named[e.ID()] = len(e.AsMap().Entries())
		}
	}
	return l
}

// decorate plans a literal as one charged before it builds.
func (l *literals) decorate(i interpreter.InterpretableV2) (interpreter.InterpretableV2, error) {
	n, ok := l.sizes[i.ID()]
	c, constructs := i.(interpreter.InterpretableConstructor)
	if !ok || !constructs {
		return i, nil
	}
	l.planned[i.ID()] = true
	return &literal{InterpretableConstructor: c, n: n, named: l.named[i.ID()], limit: l.limit}, nil
}

// literal is a list or map literal, charged what building it costs before it builds: it makes room
// for all it holds first. CEL still charges it as the literal it is. named is how many entries a
// map literal names.
type literal struct {
	interpreter.InterpretableConstructor
	n, limit uint64
	named    int
}

// Exec builds the literal, failing where it holds what no list or map a condition reads holds
// (misheld), as whatever read it would meet it: built, a list or a map holding attributes no
// condition reads was decided by its size, or by another value it held, as comparing reads only
// the smaller value whole, so `[subject.attributes] != []` held, as did size(), has() and a loop
// over one, and `[subject.attributes, 1] == [{}, 2]` failed for a kind no condition can read whole
// but was false for one declarations refuse in part, which is larger; and one holding a double that
// isn't finite was too, so `[0.0 / 0.0, "<long>"] != [1, 2]` held. No list or map a condition reads
// holds either otherwise: the subject, the resource and the request are read whole as their
// attributes are (variable), and a host's attribute holding such a double is refused (Attributes).
func (l *literal) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	chargePast(frame, l.n, l.limit)
	built := l.InterpretableConstructor.Exec(frame)
	if failed := misheld(built, l.named); failed != nil {
		return types.LabelErrNode(l.ID(), failed)
	}
	return built
}

// misheld is what building v, a list or a map a literal built, fails with, or nil: where it holds
// attributes no condition reads (refusing), or a double that isn't finite (nonFinite), as an
// element, a key or a value, reading each once, as building it was charged for, and failing as the
// attributes do where it holds both, whatever order a map's entries come in; or, for a map literal
// naming named entries, where it holds fewer, as one
// naming a key twice, which CEL builds holding the value named last: the one named before was
// dropped unread, so `{"a": subject.attributes, "a": 1}.a == 1` held where
// `{"a": 1, "a": subject.attributes}.a == 1` failed, deciding by which was built last.
func misheld(v ref.Val, named int) ref.Val {
	var refused, infinite bool
	note := func(v ref.Val) {
		refused, infinite = refused || refusing(v), infinite || nonFinite(v)
	}
	switch v := v.(type) {
	case traits.Mapper:
		if count(v) < length(named) {
			return types.NewErr("rbac: a map literal names a key twice")
		}
		if native := entries(v); native != nil {
			for k, e := range native {
				note(k)
				note(e)
			}
			break
		}
		for it := v.Iterator(); it.HasNext() == types.True; {
			k := it.Next()
			note(k)
			note(v.Get(k))
		}
	case traits.Lister:
		n, _ := v.Size().(types.Int)
		for i := types.Int(0); i < n; i++ {
			note(v.Get(i))
		}
	}
	switch {
	case refused:
		return refusal()
	case infinite:
		return incomparable()
	}
	return nil
}

func (l *literal) Eval(vars interpreter.Activation) ref.Val {
	return interpreter.EvalActivation(vars, l.Exec)
}

// keyedAttribute is a key CEL plans as an attribute: an index qualifies a map by it, and a map
// literal evaluates it, each as CEL does, once charged.
type keyedAttribute struct {
	interpreter.InterpretableAttribute
	k *keying
}

// Exec charges the key once converted, as the map reads it: one a check passes as a Go value, as
// the subject's id, is CEL's only then.
func (a *keyedAttribute) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	key := a.InterpretableAttribute.Exec(frame)
	a.k.charge(frame, a, key)
	return comparableKey(key)
}

func (a *keyedAttribute) Eval(vars interpreter.Activation) ref.Val {
	return interpreter.EvalActivation(vars, a.Exec)
}

// Qualify qualifies obj by the key, as CEL qualifies a map by an attribute.
func (a *keyedAttribute) Qualify(vars interpreter.Activation, obj any) (any, error) {
	q, err := a.qualifier(vars)
	if err != nil {
		return nil, err
	}
	return q.Qualify(vars, obj)
}

// QualifyIfPresent is Qualify where obj may lack the key, as has() qualifies a map by it.
func (a *keyedAttribute) QualifyIfPresent(vars interpreter.Activation, obj any, presenceOnly bool) (any, bool, error) {
	q, err := a.qualifier(vars)
	if err != nil {
		return nil, false, err
	}
	return q.QualifyIfPresent(vars, obj, presenceOnly)
}

// qualifier is the key, charged, as CEL qualifies a map by an attribute.
func (a *keyedAttribute) qualifier(vars interpreter.Activation) (interpreter.Qualifier, error) {
	attr := a.Attr()
	v, err := attr.Resolve(vars)
	if err != nil {
		return nil, err
	}
	a.k.charge(vars, a, v)
	// An index never runs the key, so comparableKey doesn't see it, and a double that isn't finite
	// fails as a key here too. CEL indexes by a double only for these, and by attributes no condition
	// reads, or any other map, not at all.
	switch d := v.(type) {
	case float32, float64, types.Double:
		if nonFinite(a.Adapter().NativeToValue(d)) {
			return nil, errNonFiniteKey
		}
	}
	return a.k.fac.NewQualifier(nil, attr.ID(), v, attr.IsOptional())
}

var errNonFiniteKey = errors.New("rbac: a double that isn't finite can't be a key")

// comparableKey is key, failing for a double that isn't finite, as comparing one does (nonFinite):
// CEL finds no key equal to NaN, so a map keyed by one would equal no map and hold no value, and a
// deny's `{failed / total: 1} == {0.5: 1}` would lift where both are 0.0. A condition computes
// every key it can make one of, since none is written, and no map the host passes is keyed by a
// double (Attributes). It fails for attributes no condition reads (refusing) too, which a map
// hashes as the value they are, one for every kind no condition reads: with every kind past
// maxConverted, `size({request.attributes: 1, subject.attributes: 2}) == 1` held. No list a key can
// be holds either, as building one fails (literal): keyed by a list holding NaN, a map a condition
// made equaled none, and a key not found `in` it was false, as finding whether it held one would
// read every key, uncharged.
func comparableKey(key ref.Val) ref.Val {
	if refusing(key) {
		return refusal()
	}
	if nonFinite(key) {
		return types.WrapErr(errNonFiniteKey)
	}
	return key
}

// keyedCall is a key CEL plans as a call, charged once it has run.
type keyedCall struct {
	interpreter.InterpretableCall
	k *keying
}

func (c *keyedCall) Exec(frame *interpreter.ExecutionFrame) ref.Val {
	v := c.InterpretableCall.Exec(frame)
	c.k.charge(frame, c, v)
	return comparableKey(v)
}

func (c *keyedCall) Eval(vars interpreter.Activation) ref.Val {
	return interpreter.EvalActivation(vars, c.Exec)
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
// bound, so comparing either fails, as a declared double that isn't finite does. A condition reads
// no double but CEL's own (Attributes), and no list or map holding one that isn't finite: building
// one fails (literal), and a host's attribute holding one is refused (converter).
func nonFinite(v ref.Val) bool {
	d, ok := v.(types.Double)
	return ok && (math.IsNaN(float64(d)) || math.IsInf(float64(d), 0))
}

func incomparable() ref.Val {
	return types.NewErr("rbac: a double that isn't finite can't be compared")
}

// equal is x == y, failing where comparing values a map or list holds fails, as reading a
// declared attribute passed as another type does: CEL's own comparison of maps and lists counts
// such a value as equal, so that a map holding one would equal any map with its keys. It finds the
// keys of x's maps in y's, as CEL does, which decides where a map holds keys CEL counts as equal,
// as 1 and 1u, but not a key whose size is past read, as much of the smaller value as comparing
// is charged for: the smaller holds none so large, and finding one would hash it whole uncharged.
// What a value holds is compared within one less than read, as valueSize counts each value one, so
// comparing recurses no deeper than it is charged for.
func equal(x, y ref.Val, read uint64) ref.Val {
	if read == 0 {
		return types.NewErr("rbac: comparing values this large costs more than a condition may")
	}
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
		eq := equal(a, b, read-1)
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
		// No key is found equal to NaN, so a map keyed by one would equal no map, though none a
		// check reads is (comparableKey): comparing fails where the smaller value holds one, as measured
		// reads it whole before it runs, and where only the larger does, none of the smaller's keys is
		// found equal to it, as one holding no NaN finds none of them. Searching each map's keys again
		// here took half of comparing maps nested deep. Comparing is charged for each key of either, as
		// they hold as many.
		if native := entries(xs); native != nil {
			for k, a := range native {
				if valueSize(k, read) > read {
					return types.False
				}
				if b, found := ys.Find(k); !found || !same(a, b) {
					return types.False
				}
			}
			break
		}
		for it := xs.Iterator(); it.HasNext() == types.True; {
			k := it.Next()
			if valueSize(k, read) > read {
				return types.False
			}
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

// contains is x in l, failing where comparing x with a value l holds fails and none equals it. It
// is charged for reading l, so each value l holds bounds the keys of x it finds in it.
func contains(l traits.Lister, x ref.Val) ref.Val {
	var failed ref.Val
	for it := l.Iterator(); it.HasNext() == types.True; {
		v := it.Next()
		switch eq := equal(x, v, valueSize(v, maxCost)); {
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

// measured is what comparing x with y, or finding x in y, reads, counted as valueSize counts it no
// further than past maxCost, and what comparing fails with where either is attributes no condition
// reads (refusing) or a double that isn't finite, or nil. No list or map a condition reads holds
// either, as a literal holding one fails (literal) and a host's attribute holding such a double is
// refused (converter), but the subject, the resource and the request, which are such attributes
// themselves where theirs are (variable), so whatever compares or finds either fails, wherever it
// would be reached. Found inside, comparing failed only where the smaller value held it, which
// comparing reads whole: a value found in a list or a map it read past the smaller would be read
// uncharged and, in a map, as far as the order its keys come in happens to reach, so
// `[0.0 / 0.0, "<long>"] != [1, 2]` held, decided by another value the larger held. Comparing stops
// at the smaller value, so it reads both in step, a value of the one read less at a time, until one
// is read whole, and the other only as far: a large value compared with a small one is read as far
// as the small one, and each once. A map finds a key without reading the rest.
func measured(function string, x, y ref.Val) (uint64, ref.Val) {
	switch {
	case refusing(x) || refusing(y):
		return 1, refusal()
	case nonFinite(x) || nonFinite(y):
		return 1, incomparable()
	case function != operators.In && !container(x) && !container(y):
		return min(textSize(x), textSize(y)), nil
	}
	mx, my := newMeter(x), newMeter(y)
	if function == operators.In {
		m := my
		if _, keyed := y.(traits.Mapper); keyed {
			m = mx
		}
		m.readTo(maxCost)
		return m.read, nil
	}
	for {
		m := mx
		if my.read < mx.read {
			m = my
		}
		if m.whole || m.read > maxCost {
			return m.read, nil
		}
		m.step()
	}
}

// valueSize is the cost of reading v whole, nested values included, counted no further than
// past limit: one for each value, and a tenth of a string's or bytes' length. A list or map too
// long to be within limit is past it unread, since iterating a map copies all its keys.
func valueSize(v ref.Val, limit uint64) uint64 {
	if !container(v) {
		return textSize(v)
	}
	m := newMeter(v)
	m.readTo(limit)
	return m.read
}

// entries are what m holds by its keys, where m is a map of CEL's own values, as the converter and a
// map literal make, which ranging over reads with no iterator or key found; nil for any other map.
func entries(m traits.Mapper) map[ref.Val]ref.Val {
	native, _ := m.Value().(map[ref.Val]ref.Val)
	return native
}

func container(v ref.Val) bool {
	switch v.(type) {
	case traits.Lister, traits.Mapper:
		return true
	}
	return false
}

// meter reads a value as valueSize counts it, a value at a time, so that two can be read in step
// (measured): what it has read, and whether it has read it whole. A list or map costs at least its
// length, or each entry a key and a value, as soon as it is reached, so one too long to be within
// what is read is past it unread, and each value it holds costs what reading it does past the 1 it
// was counted at (values). What it reads comes to the same in any order, and only how far it reads
// past what is compared turns on it, which nothing reads.
type meter struct {
	read  uint64
	whole bool
	// root is the value, until it is read; values are those reached, each counted at 1, and pending
	// the lists and maps whose values are still to be found.
	root    ref.Val
	values  []ref.Val
	pending []pending
}

func newMeter(v ref.Val) *meter { return &meter{root: v} }

// pending is a list whose elements from at are still to be read, or a map whose entries are, by its
// iterator, or whose value of key is: finding it hashes the key, so a key past what is read is left
// unfound.
type pending struct {
	list   traits.Lister
	at, of types.Int
	m      traits.Mapper
	it     traits.Iterator
	key    ref.Val
}

// readTo reads until m has read the value whole or more than limit.
func (m *meter) readTo(limit uint64) {
	for !m.whole && m.read <= limit {
		m.step()
	}
}

// step reads the next value. A list is dropped before its last element is read, so reading a value
// nested thousands deep, one in each, holds no more than a few.
func (m *meter) step() {
	switch {
	case m.root != nil:
		v := m.root
		m.root = nil
		m.reach(v, textSize(v))
	case len(m.values) > 0:
		v := m.values[len(m.values)-1]
		m.values = m.values[:len(m.values)-1]
		m.reach(v, textSize(v)-1)
	case len(m.pending) > 0:
		h := &m.pending[len(m.pending)-1]
		var v ref.Val
		switch {
		case h.key != nil:
			v = h.m.Get(h.key)
			m.pending = m.pending[:len(m.pending)-1]
		case h.list != nil:
			if v = h.list.Get(h.at); h.at+1 < h.of {
				h.at++
			} else {
				m.pending = m.pending[:len(m.pending)-1]
			}
		default:
			// A map's entries are found once the map is read past their least, as making an
			// iterator may copy its keys. A map of CEL's own values gives them all at once, where its
			// iterator would give a key at a time, each in a value of its own, and finding each value
			// hashes its key.
			if native := entries(h.m); native != nil && h.it == nil {
				m.pending = m.pending[:len(m.pending)-1]
				for k, v := range native {
					m.values = append(m.values, v, k)
				}
				return
			}
			if h.it == nil {
				h.it = h.m.Iterator()
			}
			if h.it.HasNext() != types.True {
				m.pending = m.pending[:len(m.pending)-1]
				return
			}
			v = h.it.Next()
			m.pending = append(m.pending, pending{m: h.m, key: v})
		}
		m.reach(v, textSize(v)-1)
	default:
		m.whole = true
	}
}

// reach counts v, which reading costs n, with the least each value it holds costs.
func (m *meter) reach(v ref.Val, n uint64) {
	switch v := v.(type) {
	case traits.Mapper:
		if k := count(v); k > 0 {
			n += 2 * k
			m.pending = append(m.pending, pending{m: v})
		}
	case traits.Lister:
		if k := count(v); k > 0 {
			of, _ := v.Size().(types.Int)
			n += k
			m.pending = append(m.pending, pending{list: v, of: of})
		}
	}
	m.read = cost.SafeAdd(m.read, n)
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
// whole condition may before running it: a call's cost is counted only once it has run. It notes
// each match it plans so in g.
func matching(patterns map[string]uint64, g *guards) *interpreter.RegexOptimization {
	return &interpreter.RegexOptimization{
		Function: overloads.Matches, RegexIndex: 1,
		Factory: func(call interpreter.InterpretableCall, pattern string) (interpreter.InterpretableCall, error) {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, err
			}
			if g.ids[call.ID()] {
				g.planned[call.ID()] = true
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

// evaluating runs as a condition is evaluated, converting as what conditions read is built,
// convertingKind as a kind's attributes are converted for it, searching as a search of a string
// runs, and loadingZone as a time zone is loaded, as a test's counters.
var evaluating, converting, convertingKind, searching, loadingZone = func() {}, func() {}, func() {}, func() {}, func() {}

// evaluate runs a condition's program on a request.
func evaluate(prg program, vars map[string]any) run {
	evaluating()
	in := &counting{vars: vars}
	out, details, err := prg.Eval(in)
	// One stopped at its limit costs at most that, past the call or step that took it there, so a
	// single condition can't spend what the check's others need. CEL doesn't stop one its keys or
	// literals take past its limit, which fails as if it had.
	spent := prg.limit
	if details != nil && details.ActualCost() != nil {
		spent = cost.SafeAdd(max(*details.ActualCost(), in.steps), in.charged)
	}
	// One that panics, as CEL can on a value of its own, costs its limit too: the call that panicked
	// isn't charged, though it can have read as much as a condition may, as comparing lists of
	// thousands of values before the one that panics does.
	var failed *types.Err
	var cancelled interpreter.EvalCancelledError
	if err != nil && !errors.As(err, &failed) && !errors.As(err, &cancelled) {
		spent = prg.limit
	}
	if err != nil || spent > prg.limit {
		return run{cost: min(spent, prg.limit)}
	}
	ok, isBool := out.Value().(bool)
	return run{held: isBool && ok, evaluated: isBool, cost: spent}
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
// Values are those Attributes names, a call converting them once into CEL's own: strings,
// numbers, booleans, bytes, times, durations, null, JSON and the protobuf well-known types, and
// lists and maps of them. One holding anything else, however deep, as a struct or a value of the
// host's own CEL type, makes the request's attributes unreadable: every condition reading any of
// them fails, as it does for the subject's or the resource's holding one.
func WithRequest(ctx context.Context, attributes map[string]any) context.Context {
	return context.WithValue(ctx, requestKey{}, maps.Clone(attributes))
}

// unrequested stands in ctx for a request's attributes where conditions are decided for a subject
// that made no request there, as an approver's label values are, beside the request of the one
// activating: they read none, a test of one's presence included, as unreadable refuses them.
// Empty, a test of an attribute's absence would hold, and a deny guarded by its presence lift.
type unrequested struct{}

// withoutRequest is ctx with no request's attributes for conditions to read.
func withoutRequest(ctx context.Context) context.Context {
	return context.WithValue(ctx, requestKey{}, unrequested{})
}

// vars is what a condition reads when s asks to do p to r, each kind's attributes converted
// (Attributes), and what converting them all may cost bounded together: past it, every kind's
// attributes refuse every read. A kind holding a value no condition can read refuses every read of
// its own, the others read as passed. The subject's and the request's are converted once for the
// call, by one converter, so a value they share is converted once (askingOf), and r's apart, from
// what they left, so each check counts all three, and a value r's share with them again.
func (a *Authorizer) vars(ctx context.Context, s Subject, p Permission, r Resource) map[string]any {
	converting()
	asked := a.askingOf(ctx, s)
	c := asked.rest
	resourced, resourceRead := c.attributes(r.Attributes)
	var requestAttributes, resourceAttributes, subjectAttributes any = unreadable, unreadable, unreadable
	if !c.over {
		requestAttributes, subjectAttributes = asked.request, asked.subject
		if resourceRead {
			resourceAttributes = declared(a.cfg.Attributes.Resource, resourced)
		}
	}
	resource := variable(map[string]any{"type": r.Type, "id": r.ID, "tenant": r.Tenant, "attributes": resourceAttributes})
	if r.Type == TenantScope && a.labelPermission(p) {
		resource = valueResource(r.Tenant)
	}
	return map[string]any{
		"subject":  variable(map[string]any{"kind": string(s.Principal.Kind), "id": s.Principal.ID, "attributes": subjectAttributes}),
		"resource": resource,
		// In UTC, as a converted time is (Attributes): string() writes a time in its own zone, so the
		// host's clock in each replica's local zone would decide by where the replica runs.
		"request": variable(map[string]any{"time": a.cfg.Now().UTC(), "attributes": requestAttributes}),
		"action":  string(p),
	}
}

// variable is m, the subject, the resource or the request as a condition reads it, read whole as its
// attributes are where they hold one refused (refusing): by name alone, as m.attributes, so whatever
// reads m whole, comparing it, finding it or in it, size() and the macros, fails, as it would reach
// them; read whole, `subject != {"kind": "user"}` held, though no condition could read what
// subject.attributes held.
func variable(m map[string]any) any {
	if attributes, ok := m["attributes"].(ref.Val); ok && refusing(attributes) {
		return refusedAttributes{Mapper: types.NewStringInterfaceMap(types.DefaultTypeAdapter, m)}
	}
	return m
}

// asking is a subject's and a request's attributes as conditions read them, and a converter
// spending what converting them left, a copy of which converts each check's resource's (rest):
// what converted them is gone, so no check knows a value by where one of theirs was, which a
// hook of the host's may have dropped since, freeing it.
type asking struct {
	rest             converter
	subject, request any
	// subjectOf and requestOf are what the host passed, kept so that where they point, which the
	// call knows them by (askingKey), is no other map's while it runs.
	subjectOf, requestOf map[string]any
}

// askingKey is what a call knows a subject's and a request's attributes by: where the host's maps
// point, and whether the request is one conditions read none of (unrequested).
type askingKey struct {
	subject, request uintptr
	unrequested      bool
}

// askingOf is s's and ctx's request's attributes as conditions read them, converted the first time
// a check of the call reads them and kept for every check after it of the same, as a change makes on
// each scope it reaches, before its transaction and again in it: converted for each, a change adding
// a member to 400 groups, its request passing a map of 40,000 entries, took 6 seconds. What they
// convert to turns on nothing else, neither the time, which vars reads for each check, nor what is
// stored, and the checks after the first read what it converted, whatever a hook of the host's
// changes of them meanwhile (Attributes). Outside a call (still), they are converted for each check.
func (a *Authorizer) askingOf(ctx context.Context, s Subject) *asking {
	_, none := ctx.Value(requestKey{}).(unrequested)
	passed, _ := ctx.Value(requestKey{}).(map[string]any)
	k := askingKey{reflect.ValueOf(s.Attributes).Pointer(), reflect.ValueOf(passed).Pointer(), none}
	if got := a.asked[k]; got != nil {
		return got
	}
	c := newConverter()
	got := &asking{subject: unreadable, request: unreadable, subjectOf: s.Attributes, requestOf: passed}
	var request map[ref.Val]ref.Val
	requestRead := !none
	if !none {
		request, requestRead = c.attributes(passed)
	}
	subjected, subjectRead := c.attributes(s.Attributes)
	got.rest = c.rest()
	if !c.over {
		if requestRead {
			got.request = declared(a.cfg.Attributes.Request, request)
		}
		if subjectRead {
			got.subject = declared(a.cfg.Attributes.Subject, subjected)
		}
	}
	if a.asked != nil {
		a.asked[k] = got
	}
	return got
}

// valueResource is the tenant as a condition deciding a label value or a power to release reads
// it: by its type and id, as checks decide those on it bare (decidedOn), and with attributes that
// refuse every read. Empty, a test of an attribute's presence would hold for what the bare tenant
// lacks, so a deny guarded by one would lift while the host's tenant has it.
func valueResource(tenant string) any {
	return variable(map[string]any{"type": TenantScope, "id": tenant, "tenant": tenant, "attributes": unreadable})
}

// valueVars is what a condition deciding a label value or a power to release for s on tenant reads:
// vars of the bare tenant, as a check decides those on it (decidedOn), with attributes that refuse
// every read (valueResource). The attributes the host passes with the tenant aren't converted, so
// they can't take the subject's or the request's past what a check converts, as a copy of the
// tenant's own vars let them, where a check and Holding decide the value.
func (a *Authorizer) valueVars(ctx context.Context, s Subject, tenant string) map[string]any {
	vars := a.vars(ctx, s, "", tenantResource(tenant))
	vars["resource"] = valueResource(tenant)
	return vars
}

// noAttributes are a kind's attributes where it has none, which every check can share.
var noAttributes = types.NewRefValMap(types.DefaultTypeAdapter, map[ref.Val]ref.Val{})

// unreadable are attributes a condition reads none of.
var unreadable = refusedAttributes{Mapper: noAttributes, all: true}

// declared is attributes, as a check converted them, as conditions read them: each one as declares
// it, converted to another type than it is declared, or failing to convert, and each one a declared
// kind doesn't declare, made an error that whatever reads it fails on, comparing it included, as
// one not passed is. CEL compares values of different types as unequal rather than fail, so
// otherwise a `!=` would hold for it, and a deny's `==` would lift. One converting made an error
// of, as one holding a double that isn't finite (converter.attributes), a declared kind refuses
// too, but a kind not declared, read as converted, can't be read at all where it holds one, as a
// kind holding a value no condition reads can't: no declarations name what its conditions read,
// and refused in part, a deny's
// `request.attributes.region == "eu" && request.attributes.risk > 0.5` lifted outside the EU for
// an infinite float64 risk, and applied for the same infinity as JSON text, `1e400`. It makes them
// so in place, as they are the check's own, reading each name once, as converting it was charged
// for.
func declared(declares map[string]AttributeType, attributes map[ref.Val]ref.Val) any {
	if len(attributes) == 0 {
		return noAttributes
	}
	refused := false
	for k, v := range attributes {
		name, _ := k.(types.String)
		t, ok := declares[string(name)]
		switch {
		case types.IsError(v) && declares == nil:
			return unreadable
		case types.IsError(v):
			refused = true
		case declares == nil:
		// One it doesn't declare a condition reads only through dyn(), which no type is checked by
		// when stored, so it fails as one of another type does.
		case !ok:
			attributes[k], refused = types.NewErr("rbac: attribute %q is not declared", string(name)), true
		case !t.takes(v):
			attributes[k], refused = types.NewErr("rbac: attribute %q is not a %s", string(name), t), true
		}
	}
	attrs := types.NewRefValMap(types.DefaultTypeAdapter, attributes)
	if refused {
		return refusedAttributes{Mapper: attrs}
	}
	return attrs
}

// refusedAttributes are a kind's attributes with some refused, as conditions read them, or the
// subject, the resource or the request holding such attributes (variable). A refused one fails what
// reads it by name, as CEL fails a value that is an error, and so does a test of its presence,
// which CEL reads from a map's keys alone and which would otherwise hold. Whatever reads the map as
// a whole, in, size(), the macros and comparing it, fails too, as it could tell a refused name from
// one never passed.
type refusedAttributes struct {
	traits.Mapper
	// all refuses every name, passed or not.
	all bool
}

// Find fails for a refused name, and with all, for any name, so a test of its presence fails too.
func (r refusedAttributes) Find(k ref.Val) (ref.Val, bool) {
	if r.all {
		return refusal(), true
	}
	return r.Mapper.Find(k)
}

// refusedAttributesType has none of a map's traits, so CEL has no size() or in for it, and a loop
// over it fails (stepping.inOrder).
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
