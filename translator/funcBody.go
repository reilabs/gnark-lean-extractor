package translator

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
)

// funcBody translates the body of a single Go function into a []stmt IR
// tree (see ir.go). The tree is rendered to Lean do-block text in one
// separate pass — see renderBlock. The walker itself carries no line
// buffer, no running indent, no last-statement cursor: those decisions are
// structural properties of the finished tree, not of the walk order.
type funcBody struct {
	t     *translator
	ec    *exprCtx
	stmts []stmt // stmts accumulated at the *current* block level

	names map[types.Object]string // Go object -> Lean name
	muts  map[types.Object]bool   // objects reassigned after definition
	// errVars records Go objects bound to a trailing `error` result. They
	// have no Lean counterpart; the only permitted use is a
	// `if err != nil { return ... }` guard, which the translator drops.
	errVars map[types.Object]bool

	api    types.Object // the frontend.API parameter
	recv   types.Object // the circuit receiver (Define only)
	isMain bool
	result []kind // helper return kinds (nil = Unit; len 1 = single value; len >1 = tuple)
	// hasErrResult marks helpers whose Go signature ends in `error`. The
	// error slot is Go-side plumbing: the Lean signature drops it, and
	// return statements truncate their trailing argument accordingly.
	hasErrResult bool
	// namedReturns holds the Lean names of Go-side named return values, in
	// declaration order. When non-nil, a bare `return` yields their
	// current bindings as a tuple.
	namedReturns []string

	tmp int
}

// push appends s to whatever block level b is currently walking into.
// Nested blocks (loop bodies, if branches) are collected via collectBlock
// below, which temporarily rebinds b.stmts to a fresh slice.
func (b *funcBody) push(s stmt) { b.stmts = append(b.stmts, s) }

// collectBlock walks stmts into a fresh []stmt without touching the outer
// block, and returns them wrapped in a block value. Used to build loop /
// if bodies. prologue, if non-nil, runs before the stmts walk (used for
// named-return / mut-param bindings inserted at function-body entry).
func (b *funcBody) collectBlock(stmts []ast.Stmt, allowReassignEnd bool, prologue func()) block {
	saved := b.stmts
	b.stmts = nil
	if prologue != nil {
		prologue()
	}
	for _, s := range stmts {
		b.stmt(s)
	}
	inner := b.stmts
	b.stmts = saved
	return block{stmts: inner, allowReassignEnd: allowReassignEnd}
}

func (b *funcBody) info() *types.Info { return b.t.pkg.TypesInfo }

// scanMut records which locals are reassigned so their bindings become
// `let mut`.
func (b *funcBody) scanMut(body *ast.BlockStmt) {
	markIdent := func(e ast.Expr) {
		if id, ok := unparen(e).(*ast.Ident); ok {
			if obj := b.info().Uses[id]; obj != nil {
				b.muts[obj] = true
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				return true
			}
			for _, l := range n.Lhs {
				switch l := l.(type) {
				case *ast.Ident:
					if obj := b.info().Uses[l]; obj != nil {
						b.muts[obj] = true
					}
				case *ast.IndexExpr:
					if id, ok := l.X.(*ast.Ident); ok {
						if obj := b.info().Uses[id]; obj != nil {
							b.muts[obj] = true
						}
					}
				case *ast.SelectorExpr:
					if id, ok := l.X.(*ast.Ident); ok {
						if obj := b.info().Uses[id]; obj != nil {
							b.muts[obj] = true
						}
					}
				}
			}
		case *ast.CallExpr:
			// `copy(dst, src)` rebinds dst under value semantics.
			if id, ok := unparen(n.Fun).(*ast.Ident); ok {
				if b, ok := b.info().Uses[id].(*types.Builtin); ok && b.Name() == "copy" && len(n.Args) == 2 {
					switch dst := unparen(n.Args[0]).(type) {
					case *ast.Ident:
						markIdent(dst)
					case *ast.SliceExpr:
						markIdent(dst.X)
					}
				}
			}
		}
		return true
	})
}

// bind registers a Lean name for a newly-declared Go object.
func (b *funcBody) bind(obj types.Object) string {
	name := sanitize(obj.Name())
	b.names[obj] = name
	return name
}

// readVars collects the tracked variables an expression reads.
func (b *funcBody) readVars(e ast.Expr) map[types.Object]bool {
	vars := map[types.Object]bool{}
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if obj := b.info().Uses[id]; obj != nil {
				if _, tracked := b.names[obj]; tracked {
					vars[obj] = true
				}
			}
		}
		return true
	})
	return vars
}

// forbidBodyAssign rejects assignments inside a loop body to any of the given
// variables. With elemWrites, element writes `xs[i] = v` are rejected too.
func (b *funcBody) forbidBodyAssign(body ast.Node, vars map[types.Object]bool, elemWrites bool, why string) {
	if len(vars) == 0 {
		return
	}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || as.Tok == token.DEFINE {
			return true
		}
		for _, l := range as.Lhs {
			switch l := l.(type) {
			case *ast.Ident:
				if obj := b.info().Uses[l]; obj != nil && vars[obj] {
					b.t.errf(as.Pos(), "the loop body reassigns %s, %s", l.Name, why)
				}
			case *ast.IndexExpr:
				if !elemWrites {
					continue
				}
				if id, ok := unparen(l.X).(*ast.Ident); ok {
					if obj := b.info().Uses[id]; obj != nil && vars[obj] {
						b.t.errf(as.Pos(), "the loop body writes elements of %s, %s", id.Name, why)
					}
				}
			}
		}
		return true
	})
}

// aliasGuard rejects binding a slice from an existing variable, element, or
// field: Go element writes propagate through such aliases, the functional
// translation's do not.
func (b *funcBody) aliasGuard(k kind, rhs ast.Expr) {
	if k.depth == 0 {
		return
	}
	switch unparen(rhs).(type) {
	case *ast.Ident, *ast.IndexExpr, *ast.SelectorExpr:
		b.t.errf(rhs.Pos(), "this binding aliases a slice — Go element writes are visible through aliases but the translation's are not; bind slices from fresh values (make, literals, function results)")
	}
}

// The three methods below are wired into b.ec at construction time as the
// scope-varying callbacks the expression walker calls back into. resolveObj
// covers both bound locals and the Circuit receiver so `circuit.method(...)`
// still lands on a synthesized literal; liftMonadic emits `let t_N ← ...`
// into the current do-block.

func (b *funcBody) resolveObj(obj types.Object, pos token.Pos) (string, bool) {
	if name, ok := b.names[obj]; ok {
		return name, true
	}
	if obj != nil && obj == b.recv {
		return b.t.synthesizeCircuitLiteral(pos), true
	}
	return "", false
}

func (b *funcBody) isAPI(obj types.Object) bool {
	return b.api != nil && obj == b.api
}

func (b *funcBody) liftMonadic(str string, _ token.Pos) string {
	tmp := fmt.Sprintf("t_%d", b.tmp)
	b.tmp++
	b.push(letBind{name: tmp, rhs: str, monadic: true})
	return tmp
}

// discardExpr translates an expression whose value is thrown away — the RHS
// of `_ = e`, a bare expression statement, or the side-effecting call inside
// an `if err := f(...); err != nil { return err }` guard. It goes through
// exprBare rather than exprTop so no Int64→F coercion fires on values the
// caller will never look at; the monadic flag is still returned so the
// caller can bind with `let _ ← ...` vs. `let _ := ...` as appropriate.
func (b *funcBody) discardExpr(e ast.Expr) (string, bool) {
	return b.ec.exprBare(e, kind{})
}
