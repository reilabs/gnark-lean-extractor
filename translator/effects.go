package translator

import (
	"go/ast"
	"go/token"
	"go/types"
)

// resultAliases returns the named variables a call's result may alias
// (per the callee's aliasReturns summary, recursing through nested calls),
// and whether it may alias something unnamed (a field or slice element).
func (t *translator) resultAliases(call *ast.CallExpr) (map[types.Object]bool, bool) {
	fn, _ := t.callee(call).(*types.Func)
	objs := map[types.Object]bool{}
	external := false
	for q := range t.emit.funcReg.aliasReturns(fn) {
		if q >= len(call.Args) {
			continue
		}
		switch arg := unparen(call.Args[q]).(type) {
		case *ast.Ident:
			if obj := t.pkg.TypesInfo.Uses[arg]; obj != nil {
				objs[obj] = true
			}
		case *ast.CallExpr:
			o2, e2 := t.resultAliases(arg)
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

// analyzeEffects enforces the invariant the translation's value semantics
// rely on: every slice backing array has at most one live name. It computes
// two per-function summaries (dirtyParams / aliasReturns), stores them on
// the funcSlot, and rejects call sites that would let Go's aliasing become
// observable. A written-position argument must be a fresh value or the
// rebinding form `x = f(..., x)` (the write lands on a backing whose only
// name is immediately rebound to the equal-by-induction result); a result
// that may alias an argument may only be bound back to that same variable.
//
// The work is split across four passes on effectAnalysis below.
func (t *translator) analyzeEffects(fn *types.Func, body *ast.BlockStmt, paramObjs []types.Object) {
	paramIdx := map[types.Object]int{}
	for i, o := range paramObjs {
		if o != nil {
			paramIdx[o] = i
		}
	}
	a := &effectAnalysis{t: t, fn: fn, body: body, info: t.pkg.TypesInfo, paramIdx: paramIdx}
	dirty := a.computeDirtyParams()
	if fn != nil {
		t.emit.funcReg.slot(fn).dirtyParams = dirty
	}
	rebinds, returnCalls := a.collectRebindsReturns()
	if aliases := a.computeAliasReturns(); fn != nil && len(aliases) > 0 {
		t.emit.funcReg.slot(fn).aliasReturns = aliases
	}
	a.enforceCallSites(rebinds, returnCalls)
}

// effectAnalysis carries the state shared by analyzeEffects' four passes.
type effectAnalysis struct {
	t        *translator
	fn       *types.Func // nil for Define
	body     *ast.BlockStmt
	info     *types.Info
	paramIdx map[types.Object]int
}

// paramOf returns the parameter index of e, or -1 if e is not (an ident
// bound to) a param.
func (a *effectAnalysis) paramOf(e ast.Expr) int {
	if id, ok := unparen(e).(*ast.Ident); ok {
		if i, ok := a.paramIdx[a.info.Uses[id]]; ok {
			return i
		}
	}
	return -1
}

// computeDirtyParams walks the body flagging slice parameters whose backing
// array is written — either by a direct `xs[i] = v` or by being passed to a
// callee that itself writes.
func (a *effectAnalysis) computeDirtyParams() map[int]bool {
	dirty := map[int]bool{}
	mark := func(e ast.Expr) {
		if i := a.paramOf(e); i >= 0 {
			dirty[i] = true
		}
	}
	ast.Inspect(a.body, func(n ast.Node) bool {
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
			fn, _ := a.t.callee(n).(*types.Func)
			for p := range a.t.emit.funcReg.dirtyParams(fn) {
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
// assignments and calls in return position — both patterns the pass 4
// enforcement below needs to distinguish from other call shapes.
func (a *effectAnalysis) collectRebindsReturns() (
	rebinds map[*ast.CallExpr]types.Object,
	returnCalls map[*ast.CallExpr]bool,
) {
	rebinds = map[*ast.CallExpr]types.Object{}
	returnCalls = map[*ast.CallExpr]bool{}
	ast.Inspect(a.body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == 1 && len(n.Rhs) == 1 {
				if lhs, ok := n.Lhs[0].(*ast.Ident); ok {
					if call, ok := unparen(n.Rhs[0]).(*ast.CallExpr); ok {
						if n.Tok == token.DEFINE {
							rebinds[call] = a.info.Defs[lhs]
						} else {
							rebinds[call] = a.info.Uses[lhs]
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
func (a *effectAnalysis) computeAliasReturns() map[int]bool {
	if a.fn == nil {
		return nil
	}
	sig := a.fn.Type().(*types.Signature)
	results, _ := stripTrailingError(sig.Results())
	if results.Len() != 1 || isEmptyInterface(results.At(0).Type()) ||
		a.t.classify(results.At(0).Type(), a.fn.Pos()).depth == 0 {
		return nil
	}
	ret := map[int]bool{}
	ast.Inspect(a.body, func(n ast.Node) bool {
		rs, ok := n.(*ast.ReturnStmt)
		if !ok || len(rs.Results) != 1 {
			return true
		}
		switch r := unparen(rs.Results[0]).(type) {
		case *ast.Ident:
			if i := a.paramOf(r); i >= 0 {
				ret[i] = true
			}
		case *ast.CallExpr:
			objs, external := a.t.resultAliases(r)
			if external {
				a.t.errf(rs.Pos(), "returns a slice that may alias a field or slice element")
			}
			for o := range objs {
				if i, ok := a.paramIdx[o]; ok {
					ret[i] = true
				}
			}
		case *ast.IndexExpr, *ast.SelectorExpr:
			a.t.errf(rs.Pos(), "returns an alias of a slice element or field")
		}
		return true
	})
	return ret
}

// enforceCallSites walks every call and rejects arg/result shapes that
// would let Go-visible aliasing survive the translation. Written-position
// args must be fresh values or the rebind form `x = f(..., x)`; results
// that may alias an argument must be bound back to that same variable.
func (a *effectAnalysis) enforceCallSites(
	rebinds map[*ast.CallExpr]types.Object,
	returnCalls map[*ast.CallExpr]bool,
) {
	ast.Inspect(a.body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee, _ := a.t.callee(call).(*types.Func)
		for p := range a.t.emit.funcReg.dirtyParams(callee) {
			if p >= len(call.Args) {
				continue
			}
			switch arg := unparen(call.Args[p]).(type) {
			case *ast.CompositeLit:
				// Fresh value: nothing else observes its backing array.
			case *ast.CallExpr:
				if objs, external := a.t.resultAliases(arg); external || len(objs) > 0 {
					a.t.errf(call.Args[p].Pos(),
						"%s writes the elements of this argument, whose backing array is aliased elsewhere",
						callee.Name())
				}
			case *ast.Ident:
				obj := a.info.Uses[arg]
				if obj == nil || rebinds[call] != obj {
					a.t.errf(arg.Pos(),
						"%s writes the elements of this argument, which Go callers observe through aliasing but the translation does not — use the form %s = %s(..., %s)",
						callee.Name(), arg.Name, callee.Name(), arg.Name)
				}
				for j, other := range call.Args {
					if j == p {
						continue
					}
					if id, ok := unparen(other).(*ast.Ident); ok && a.info.Uses[id] == obj {
						a.t.errf(other.Pos(),
							"%s is passed to %s more than once while %s writes its elements — Go sees those writes through both parameters, the translation does not",
							arg.Name, callee.Name(), callee.Name())
					}
				}
			default:
				a.t.errf(call.Args[p].Pos(),
					"%s writes the elements of this argument — pass a variable in the form x = %s(..., x) or a fresh value",
					callee.Name(), callee.Name())
			}
		}
		if returnCalls[call] {
			return true
		}
		objs, external := a.t.resultAliases(call)
		if external {
			a.t.errf(call.Pos(), "the result of %s may alias a field or slice element", callee.Name())
		}
		for o := range objs {
			if o != rebinds[call] {
				a.t.errf(call.Pos(),
					"the result of %s may alias %s — bind it back to the same variable (%s = %s(..., %s)) so the backing array keeps a single name",
					callee.Name(), o.Name(), o.Name(), callee.Name(), o.Name())
			}
		}
		return true
	})
}
