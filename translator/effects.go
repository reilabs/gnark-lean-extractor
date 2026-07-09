package translator

import (
	"go/ast"
	"go/token"
	"go/types"
)

// effectSummary is the read-visible per-parameter effect information a
// function exposes to its callers' call-site enforcement.
type effectSummary struct {
	// dirtyParams: signature indices of slice parameters whose backing
	// array the function (transitively) writes.
	dirtyParams map[int]bool
	// aliasReturns: signature indices of parameters whose backing array
	// the single result may alias.
	aliasReturns map[int]bool
}

// analyzeEffects enforces the invariant the translation's value semantics
// rely on: every slice backing array has at most one live name. It runs in
// three phases:
//
//  1. summarize — walk the body, derive fn's effectSummary from the body
//     itself and from callee summaries. No writes to shared state.
//  2. attach   — store the summary on fn's slot in one shot, so any
//     later-analyzed caller sees a complete view (both maps set, never
//     one without the other).
//  3. enforce  — walk call sites and reject arg/result shapes that would
//     let Go-visible aliasing survive the translation.
func (b *funcBody) analyzeEffects(fn *types.Func, body *ast.BlockStmt, paramObjs []types.Object) {
	info := b.pkg.TypesInfo
	reg := b.emit.funcReg
	paramIdx := map[types.Object]int{}
	for i, o := range paramObjs {
		if o != nil {
			paramIdx[o] = i
		}
	}
	summary := effectSummary{
		dirtyParams:  b.computeDirtyParams(info, reg, body, paramIdx),
		aliasReturns: b.computeAliasReturns(fn, body, paramIdx),
	}
	if fn != nil {
		reg.slot(fn).summary = summary
	}
	rebinds, returnCalls := collectRebindsReturns(info, body)
	b.enforceCallSites(body, rebinds, returnCalls)
}

// paramOf returns the parameter index of e, or -1 if e is not (an ident
// bound to) a param.
func paramOf(info *types.Info, paramIdx map[types.Object]int, e ast.Expr) int {
	if id, ok := unparen(e).(*ast.Ident); ok {
		if i, ok := paramIdx[info.Uses[id]]; ok {
			return i
		}
	}
	return -1
}

// resultAliases returns the named variables a call's result may alias
// (per the callee's aliasReturns summary, recursing through nested calls),
// and whether it may alias something unnamed (a field or slice element).
func (b *funcBody) resultAliases(call *ast.CallExpr) (map[types.Object]bool, bool) {
	info := b.pkg.TypesInfo
	fn, _ := b.callee(call).(*types.Func)
	objs := map[types.Object]bool{}
	external := false
	for q := range b.emit.funcReg.summary(fn).aliasReturns {
		if q >= len(call.Args) {
			continue
		}
		switch arg := unparen(call.Args[q]).(type) {
		case *ast.Ident:
			if obj := info.Uses[arg]; obj != nil {
				objs[obj] = true
			}
		case *ast.CallExpr:
			o2, e2 := b.resultAliases(arg)
			for o := range o2 {
				objs[o] = true
			}
			external = external || e2
		case *ast.CompositeLit:
			// Fresh backing with no other name; aliasing it is harmless.
		default:
			external = true
		}
	}
	return objs, external
}

// computeDirtyParams walks the body flagging slice parameters whose backing
// array is written — either by a direct `xs[i] = v` or by being passed to a
// callee that itself writes.
func (b *funcBody) computeDirtyParams(info *types.Info, reg *funcRegistry, body *ast.BlockStmt, paramIdx map[types.Object]int) map[int]bool {
	dirty := map[int]bool{}
	mark := func(e ast.Expr) {
		if i := paramOf(info, paramIdx, e); i >= 0 {
			dirty[i] = true
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok != token.DEFINE {
				for _, l := range n.Lhs {
					if ix, ok := l.(*ast.IndexExpr); ok {
						mark(ix.X)
					}
				}
			}
		case *ast.CallExpr:
			fn, _ := b.callee(n).(*types.Func)
			for p := range reg.summary(fn).dirtyParams {
				if p < len(n.Args) {
					mark(n.Args[p])
				}
			}
		}
		return true
	})
	return dirty
}

// collectRebindsReturns records single-target `x = f(...)` / `x := f(...)`
// assignments and calls in return position — both patterns enforceCallSites
// needs to distinguish from other call shapes.
func collectRebindsReturns(info *types.Info, body *ast.BlockStmt) (
	rebinds map[*ast.CallExpr]types.Object,
	returnCalls map[*ast.CallExpr]bool,
) {
	rebinds = map[*ast.CallExpr]types.Object{}
	returnCalls = map[*ast.CallExpr]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == 1 && len(n.Rhs) == 1 {
				if lhs, ok := n.Lhs[0].(*ast.Ident); ok {
					if call, ok := unparen(n.Rhs[0]).(*ast.CallExpr); ok {
						if n.Tok == token.DEFINE {
							rebinds[call] = info.Defs[lhs]
						} else {
							rebinds[call] = info.Uses[lhs]
						}
					}
				}
			}
		case *ast.ReturnStmt:
			if len(n.Results) == 1 {
				if call, ok := unparen(n.Results[0]).(*ast.CallExpr); ok {
					returnCalls[call] = true
				}
			}
		}
		return true
	})
	return rebinds, returnCalls
}

// computeAliasReturns walks return statements to compute which parameters
// the result may alias. In accepted programs a local slice never aliases a
// param (bindings that would create such an alias are rejected), so only
// param names and returned calls matter. Returns nil for functions where
// alias analysis doesn't apply (Define, non-slice results, `interface{}`
// returns whose concrete type is inferred elsewhere).
func (b *funcBody) computeAliasReturns(fn *types.Func, body *ast.BlockStmt, paramIdx map[types.Object]int) map[int]bool {
	if fn == nil {
		return nil
	}
	info := b.pkg.TypesInfo
	sig := fn.Type().(*types.Signature)
	results, _ := stripTrailingError(sig.Results())
	if results.Len() != 1 || isEmptyInterface(results.At(0).Type()) ||
		b.classify(results.At(0).Type(), fn.Pos()).depth == 0 {
		return nil
	}
	ret := map[int]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		rs, ok := n.(*ast.ReturnStmt)
		if !ok || len(rs.Results) != 1 {
			return true
		}
		switch r := unparen(rs.Results[0]).(type) {
		case *ast.Ident:
			if i := paramOf(info, paramIdx, r); i >= 0 {
				ret[i] = true
			}
		case *ast.CallExpr:
			objs, external := b.resultAliases(r)
			if external {
				b.errf(rs.Pos(), "returns a slice that may alias a field or slice element")
			}
			for o := range objs {
				if i, ok := paramIdx[o]; ok {
					ret[i] = true
				}
			}
		case *ast.IndexExpr, *ast.SelectorExpr:
			b.errf(rs.Pos(), "returns an alias of a slice element or field")
		}
		return true
	})
	return ret
}

// enforceCallSites walks every call and rejects arg/result shapes that
// would let Go-visible aliasing survive the translation. Written-position
// args must be fresh values or the rebind form `x = f(..., x)`; results
// that may alias an argument must be bound back to that same variable.
func (b *funcBody) enforceCallSites(
	body *ast.BlockStmt,
	rebinds map[*ast.CallExpr]types.Object,
	returnCalls map[*ast.CallExpr]bool,
) {
	info := b.pkg.TypesInfo
	reg := b.emit.funcReg
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee, _ := b.callee(call).(*types.Func)
		for p := range reg.summary(callee).dirtyParams {
			if p >= len(call.Args) {
				continue
			}
			switch arg := unparen(call.Args[p]).(type) {
			case *ast.CompositeLit:
				// Fresh value: nothing else observes its backing array.
			case *ast.CallExpr:
				if objs, external := b.resultAliases(arg); external || len(objs) > 0 {
					b.errf(call.Args[p].Pos(),
						"%s writes the elements of this argument, whose backing array is aliased elsewhere",
						callee.Name())
				}
			case *ast.Ident:
				obj := info.Uses[arg]
				if obj == nil || rebinds[call] != obj {
					b.errf(arg.Pos(),
						"%s writes the elements of this argument, which Go callers observe through aliasing but the translation does not — use the form %s = %s(..., %s)",
						callee.Name(), arg.Name, callee.Name(), arg.Name)
				}
				for j, other := range call.Args {
					if j == p {
						continue
					}
					if id, ok := unparen(other).(*ast.Ident); ok && info.Uses[id] == obj {
						b.errf(other.Pos(),
							"%s is passed to %s more than once while %s writes its elements — Go sees those writes through both parameters, the translation does not",
							arg.Name, callee.Name(), callee.Name())
					}
				}
			default:
				b.errf(call.Args[p].Pos(),
					"%s writes the elements of this argument — pass a variable in the form x = %s(..., x) or a fresh value",
					callee.Name(), callee.Name())
			}
		}
		if returnCalls[call] {
			return true
		}
		objs, external := b.resultAliases(call)
		if external {
			b.errf(call.Pos(), "the result of %s may alias a field or slice element", callee.Name())
		}
		for o := range objs {
			if o != rebinds[call] {
				b.errf(call.Pos(),
					"the result of %s may alias %s — bind it back to the same variable (%s = %s(..., %s)) so the backing array keeps a single name",
					callee.Name(), o.Name(), o.Name(), callee.Name(), o.Name())
			}
		}
		return true
	})
}
