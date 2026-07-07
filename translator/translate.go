package translator

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"strings"
)

// funcTr translates the body of a single Go function into lines of a Lean
// do-block.
type funcTr struct {
	t      *translator
	lines  []string
	indent int

	names map[types.Object]string // Go object -> Lean name
	muts  map[types.Object]bool   // objects reassigned after definition

	api    types.Object // the frontend.API parameter
	recv   types.Object // the circuit receiver (Define only)
	isMain bool
	result []kind // helper return kinds (nil = Unit; len 1 = single value; len >1 = tuple)

	tmp  int
	last lastStmt
}

type lastStmt int

const (
	lastNone     lastStmt = iota
	lastLet               // `let x := ...` / `let x ← ...` — cannot end a do-block
	lastReassign          // `x := ...` / `x ← ...` — valid at the end of loop/if bodies
	lastExpr              // an expression — valid at the end of any do-block
)

func (f *funcTr) emit(s string) {
	f.lines = append(f.lines, strings.Repeat("  ", f.indent)+s)
}

func (f *funcTr) info() *types.Info { return f.t.pkg.TypesInfo }

// scanMut records which locals are reassigned so their bindings become
// `let mut`.
func (f *funcTr) scanMut(body *ast.BlockStmt) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				return true
			}
			for _, l := range n.Lhs {
				switch l := l.(type) {
				case *ast.Ident:
					if obj := f.info().Uses[l]; obj != nil {
						f.muts[obj] = true
					}
				case *ast.IndexExpr:
					if id, ok := l.X.(*ast.Ident); ok {
						if obj := f.info().Uses[id]; obj != nil {
							f.muts[obj] = true
						}
					}
				}
			}
		}
		return true
	})
}

// block translates a statement list as one do-sequence, appending `pure ()`
// when the sequence would otherwise end in a binding. Loop and if bodies may
// end in a reassignment of a `mut` variable; function bodies may not.
func (f *funcTr) block(stmts []ast.Stmt, allowReassignEnd bool, prologue func()) {
	saved := f.last
	f.last = lastNone
	if prologue != nil {
		prologue()
	}
	for _, s := range stmts {
		f.stmt(s)
	}
	if f.last == lastNone || f.last == lastLet || (f.last == lastReassign && !allowReassignEnd) {
		f.emit("pure ()")
	}
	f.last = saved
}

func (f *funcTr) stmt(s ast.Stmt) {
	switch s := s.(type) {
	case *ast.BlockStmt:
		for _, st := range s.List {
			f.stmt(st)
		}
	case *ast.AssignStmt:
		f.assign(s)
	case *ast.ExprStmt:
		f.exprStmt(s)
	case *ast.ForStmt:
		f.forStmt(s)
	case *ast.RangeStmt:
		f.rangeStmt(s)
	case *ast.IfStmt:
		f.ifStmt(s)
	case *ast.ReturnStmt:
		f.returnStmt(s)
	default:
		f.t.errf(s.Pos(), "unsupported statement %T", s)
	}
}

// bind registers a Lean name for a newly-declared Go object.
func (f *funcTr) bind(obj types.Object) string {
	name := sanitize(obj.Name())
	f.names[obj] = name
	return name
}

// readVars collects the tracked variables an expression reads.
func (f *funcTr) readVars(e ast.Expr) map[types.Object]bool {
	vars := map[types.Object]bool{}
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if obj := f.info().Uses[id]; obj != nil {
				if _, tracked := f.names[obj]; tracked {
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
func (f *funcTr) forbidBodyAssign(body ast.Node, vars map[types.Object]bool, elemWrites bool, why string) {
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
				if obj := f.info().Uses[l]; obj != nil && vars[obj] {
					f.t.errf(as.Pos(), "the loop body reassigns %s, %s", l.Name, why)
				}
			case *ast.IndexExpr:
				if !elemWrites {
					continue
				}
				if id, ok := unparen(l.X).(*ast.Ident); ok {
					if obj := f.info().Uses[id]; obj != nil && vars[obj] {
						f.t.errf(as.Pos(), "the loop body writes elements of %s, %s", id.Name, why)
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
func (f *funcTr) aliasGuard(k kind, rhs ast.Expr) {
	if k.depth == 0 {
		return
	}
	switch unparen(rhs).(type) {
	case *ast.Ident, *ast.IndexExpr, *ast.SelectorExpr:
		f.t.errf(rhs.Pos(), "this binding aliases a slice — Go element writes are visible through aliases but the translation's are not; bind slices from fresh values (make, literals, function results)")
	}
}

func (f *funcTr) assign(s *ast.AssignStmt) {
	if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		f.t.errf(s.Pos(), "multi-assignment is not supported")
	}
	rhs := s.Rhs[0]
	switch s.Tok {
	case token.DEFINE:
		id, ok := s.Lhs[0].(*ast.Ident)
		if !ok {
			f.t.errf(s.Pos(), "unsupported := target")
		}
		if id.Name == "_" {
			f.discard(rhs)
			return
		}
		obj := f.info().Defs[id]
		k := f.t.classify(obj.Type(), id.Pos())
		f.aliasGuard(k, rhs)
		str, monadic := f.exprTop(rhs, k)
		mut := ""
		if f.muts[obj] {
			mut = "mut "
		}
		// Ascribe Int64 bindings so bare numerals don't default to Nat.
		ascr := ""
		if k.goInt {
			ascr = " : Int64"
		}
		name := f.bind(obj)
		if monadic {
			f.emit(fmt.Sprintf("let %s%s%s ← %s", mut, name, ascr, str))
		} else {
			f.emit(fmt.Sprintf("let %s%s%s := %s", mut, name, ascr, str))
		}
		f.last = lastLet
	case token.ASSIGN:
		switch lhs := s.Lhs[0].(type) {
		case *ast.Ident:
			if lhs.Name == "_" {
				f.discard(rhs)
				return
			}
			obj := f.info().Uses[lhs]
			name, ok := f.names[obj]
			if !ok {
				f.t.errf(lhs.Pos(), "assignment to unknown variable %s", lhs.Name)
			}
			k := f.t.classify(obj.Type(), lhs.Pos())
			f.aliasGuard(k, rhs)
			str, monadic := f.exprTop(rhs, k)
			if monadic {
				f.emit(fmt.Sprintf("%s ← %s", name, str))
			} else {
				f.emit(fmt.Sprintf("%s := %s", name, str))
			}
			f.last = lastReassign
		case *ast.IndexExpr:
			id, ok := lhs.X.(*ast.Ident)
			if !ok {
				f.t.errf(lhs.Pos(), "only simple `xs[i] = v` assignments are supported")
			}
			obj := f.info().Uses[id]
			name, ok := f.names[obj]
			if !ok {
				f.t.errf(lhs.Pos(), "assignment to unknown variable %s", id.Name)
			}
			bk := f.kindOf(lhs.X)
			idx := f.natAtom(lhs.Index)
			val := f.atom(rhs, bk.elem())
			f.emit(fmt.Sprintf("%s := %s.set %s %s", name, name, idx, val))
			f.last = lastReassign
		default:
			f.t.errf(s.Pos(), "unsupported assignment target %T", lhs)
		}
	default:
		f.t.errf(s.Pos(), "unsupported assignment operator %s", s.Tok)
	}
}

// discard translates `_ = e` / `_ := e`.
func (f *funcTr) discard(rhs ast.Expr) {
	str, monadic := f.exprTop(rhs, kind{})
	if monadic {
		f.emit("let _ ← " + str)
	} else {
		f.emit("let _ := " + str)
	}
	f.last = lastLet
}

func (f *funcTr) exprStmt(s *ast.ExprStmt) {
	call, ok := s.X.(*ast.CallExpr)
	if !ok {
		f.t.errf(s.Pos(), "unsupported expression statement")
	}
	str, monadic := f.exprTop(call, kind{})
	switch {
	case monadic && f.callIsUnit(call):
		f.emit(str)
		f.last = lastExpr
	case monadic:
		f.emit("let _ ← " + str)
		f.last = lastLet
	default:
		f.emit("let _ := " + str)
		f.last = lastLet
	}
}

// callIsUnit reports whether a call produces no value (assertions, void
// helpers), so it can stand alone as a do-statement.
func (f *funcTr) callIsUnit(call *ast.CallExpr) bool {
	if sel, ok := unparen(call.Fun).(*ast.SelectorExpr); ok {
		if id, ok := unparen(sel.X).(*ast.Ident); ok && f.api != nil && f.info().Uses[id] == f.api {
			switch sel.Sel.Name {
			case "AssertIsEqual", "AssertIsDifferent", "AssertIsBoolean", "AssertIsLessOrEqual":
				return true
			}
			return false
		}
	}
	if fn, ok := f.callee(call).(*types.Func); ok {
		return fn.Type().(*types.Signature).Results().Len() == 0
	}
	return false
}

func (f *funcTr) forStmt(s *ast.ForStmt) {
	init, ok := s.Init.(*ast.AssignStmt)
	if !ok || init.Tok != token.DEFINE || len(init.Lhs) != 1 {
		f.t.errf(s.Pos(), "only `for i := lo; i < hi; i++` loops are supported")
	}
	id := init.Lhs[0].(*ast.Ident)
	obj := f.info().Defs[id]
	cond, ok := s.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.LSS {
		f.t.errf(s.Pos(), "only `i < hi` loop conditions are supported")
	}
	if cid, ok := unparen(cond.X).(*ast.Ident); !ok || f.info().Uses[cid] != obj {
		f.t.errf(s.Pos(), "loop condition must test the loop variable")
	}
	post, ok := s.Post.(*ast.IncDecStmt)
	if !ok || post.Tok != token.INC {
		f.t.errf(s.Pos(), "only `i++` loop increments are supported")
	}
	// Go re-evaluates the bound every iteration; the translation evaluates it
	// once at loop entry. Reject bodies that reassign what the bound reads.
	// Element writes are fine: they cannot change a length.
	f.forbidBodyAssign(s.Body, f.readVars(cond.Y), false,
		"which the loop bound reads — Go re-evaluates the bound every iteration, the translation does not")
	lo := f.atom(init.Rhs[0], kind{goInt: true})
	hi := f.atom(cond.Y, kind{goInt: true})
	name := f.bind(obj)
	f.emit(fmt.Sprintf("for %s in goRange %s %s do", name, lo, hi))
	f.indent++
	f.block(s.Body.List, true, nil)
	f.indent--
	f.last = lastExpr
}

func (f *funcTr) rangeStmt(s *ast.RangeStmt) {
	if s.Key == nil {
		f.t.errf(s.Pos(), "`for range` without variables is not supported")
	}
	if s.Tok != token.DEFINE {
		f.t.errf(s.Pos(), "only `for i, v := range` loops are supported")
	}
	xk := f.kindOf(s.X)
	if xk.goInt || xk.depth < 1 {
		f.t.errf(s.X.Pos(), "range is only supported over slices/arrays of Variable")
	}
	if xk.depth > 1 && s.Value != nil {
		f.t.errf(s.Value.Pos(), "ranging with a value over nested slices aliases the inner slices")
	}
	// Go ranges over the backing array captured at loop entry; the translated
	// body reads the variable's current value. Reject bodies that write the
	// ranged slice in any way.
	f.forbidBodyAssign(s.Body, f.readVars(s.X), true,
		"which is being ranged over — Go iterates the backing array captured at loop entry")
	xs := f.atom(s.X, xk)

	keyId, _ := s.Key.(*ast.Ident)
	var valId *ast.Ident
	if s.Value != nil {
		valId, _ = s.Value.(*ast.Ident)
		if valId != nil && valId.Name == "_" {
			valId = nil
		}
	}

	if keyId.Name == "_" && valId != nil {
		// `for _, v := range xs` iterates directly.
		vname := f.bind(f.info().Defs[valId])
		f.emit(fmt.Sprintf("for %s in %s do", vname, xs))
		f.indent++
		f.block(s.Body.List, true, nil)
		f.indent--
		f.last = lastExpr
		return
	}

	iname := f.bind(f.info().Defs[keyId])
	f.emit(fmt.Sprintf("for %s in goRange 0 (Int64.ofNat %s.length) do", iname, xs))
	f.indent++
	var prologue func()
	if valId != nil {
		vname := f.bind(f.info().Defs[valId])
		prologue = func() {
			f.emit(fmt.Sprintf("let %s := %s[%s.toInt.toNat]!", vname, xs, iname))
			f.last = lastLet
		}
	}
	f.block(s.Body.List, true, prologue)
	f.indent--
	f.last = lastExpr
}

func (f *funcTr) ifStmt(s *ast.IfStmt) {
	if s.Init != nil {
		f.t.errf(s.Pos(), "if statements with init clauses are not supported")
	}
	f.emit(fmt.Sprintf("if %s then", f.cond(s.Cond)))
	f.indent++
	f.block(s.Body.List, true, nil)
	f.indent--
	if s.Else != nil {
		els, ok := s.Else.(*ast.BlockStmt)
		if !ok {
			f.t.errf(s.Else.Pos(), "else-if chains are not supported")
		}
		f.emit("else")
		f.indent++
		f.block(els.List, true, nil)
		f.indent--
	}
	f.last = lastExpr
}

// cond translates a Go-level (size/config) boolean expression into a Lean
// decidable proposition.
func (f *funcTr) cond(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return f.cond(e.X)
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND:
			return fmt.Sprintf("(%s ∧ %s)", f.cond(e.X), f.cond(e.Y))
		case token.LOR:
			return fmt.Sprintf("(%s ∨ %s)", f.cond(e.X), f.cond(e.Y))
		}
		if !f.kindOf(e.X).goInt {
			f.t.errf(e.Pos(), "conditions may only compare Go integers")
		}
		var op string
		switch e.Op {
		case token.EQL:
			op = "="
		case token.NEQ:
			op = "≠"
		case token.LSS:
			op = "<"
		case token.LEQ:
			op = "≤"
		case token.GTR:
			op = ">"
		case token.GEQ:
			op = "≥"
		default:
			f.t.errf(e.Pos(), "unsupported condition operator %s", e.Op)
		}
		return fmt.Sprintf("%s %s %s", f.atom(e.X, kind{goInt: true}), op, f.atom(e.Y, kind{goInt: true}))
	}
	f.t.errf(e.Pos(), "unsupported condition %T", e)
	return ""
}

func (f *funcTr) returnStmt(s *ast.ReturnStmt) {
	if f.isMain {
		// Define returns error; only `return nil` is supported.
		if len(s.Results) != 1 || !f.info().Types[s.Results[0]].IsNil() {
			f.t.errf(s.Pos(), "Define may only `return nil`")
		}
		return
	}
	if len(s.Results) == 0 {
		f.emit("pure ()")
		f.last = lastExpr
		return
	}
	if len(f.result) == 0 {
		f.t.errf(s.Pos(), "unexpected return value")
	}
	if len(s.Results) != len(f.result) {
		f.t.errf(s.Pos(), "return count mismatch: got %d, want %d", len(s.Results), len(f.result))
	}
	if len(f.result) == 1 {
		str, monadic := f.exprTop(s.Results[0], f.result[0])
		if monadic {
			f.emit(str)
		} else {
			f.emit("return " + str)
		}
		f.last = lastExpr
		return
	}
	parts := make([]string, len(s.Results))
	for i, r := range s.Results {
		parts[i] = f.atom(r, f.result[i])
	}
	f.emit("return (" + strings.Join(parts, ", ") + ")")
	f.last = lastExpr
}

// ---- expressions ----

func (f *funcTr) kindOf(e ast.Expr) kind {
	return f.t.classify(f.info().TypeOf(e), e.Pos())
}

var atomRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.']*$|^[0-9]+$`)

func wrapParen(s string) string {
	if atomRe.MatchString(s) {
		return s
	}
	if len(s) > 1 && s[0] == '(' && s[len(s)-1] == ')' {
		depth := 0
		wholly := true
		for i, r := range s {
			switch r {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i != len(s)-1 {
					wholly = false
				}
			}
		}
		if wholly {
			return s
		}
	}
	return "(" + s + ")"
}

// atom translates an expression to a Lean term suitable for use as a function
// argument: monadic subexpressions are lifted into fresh bindings, compound
// pure expressions are parenthesized.
func (f *funcTr) atom(e ast.Expr, want kind) string {
	str, monadic := f.exprTop(e, want)
	if monadic {
		tmp := fmt.Sprintf("t_%d", f.tmp)
		f.tmp++
		f.emit(fmt.Sprintf("let %s ← %s", tmp, str))
		f.last = lastLet
		return tmp
	}
	return wrapParen(str)
}

// exprTop translates an expression, returning the Lean term and whether it is
// monadic (`Circuit _`-valued) at the top level. A Go integer expression in a
// Variable position is a gnark constant: it enters the field through
// .toInt mod p.
func (f *funcTr) exprTop(e ast.Expr, want kind) (string, bool) {
	str, monadic := f.exprBare(e, want)
	if !monadic && !want.goInt && want.depth == 0 && f.isIntValued(e) {
		return fmt.Sprintf("((%s).toInt : F)", str), false
	}
	return str, monadic
}

// isIntValued reports whether e is a non-constant Go integer expression
// (constants render directly at the wanted type instead).
func (f *funcTr) isIntValued(e ast.Expr) bool {
	if tv, ok := f.info().Types[e]; ok && tv.Value != nil {
		return false
	}
	typ := f.info().TypeOf(e)
	if typ == nil {
		return false
	}
	b, ok := typ.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsInteger != 0
}

func (f *funcTr) exprBare(e ast.Expr, want kind) (string, bool) {
	if tv, ok := f.info().Types[e]; ok && tv.Value != nil {
		return f.renderConst(tv.Value, want, e.Pos()), false
	}
	switch e := e.(type) {
	case *ast.ParenExpr:
		return f.exprBare(e.X, want)
	case *ast.Ident:
		if name, ok := f.names[f.info().Uses[e]]; ok {
			return name, false
		}
		f.t.errf(e.Pos(), "unknown identifier %s", e.Name)
	case *ast.SelectorExpr:
		if sel, ok := f.info().Selections[e]; ok && sel.Kind() == types.FieldVal {
			if name, ok := f.names[sel.Obj()]; ok {
				return name, false
			}
		}
		f.t.errf(e.Pos(), "unsupported selector expression")
	case *ast.IndexExpr:
		base := f.atom(e.X, f.kindOf(e.X))
		return fmt.Sprintf("%s[%s]!", base, f.natRaw(e.Index)), false
	case *ast.CallExpr:
		return f.call(e, want)
	case *ast.CompositeLit:
		k := f.t.classify(f.info().TypeOf(e), e.Pos())
		if k.goInt || k.depth == 0 {
			f.t.errf(e.Pos(), "unsupported composite literal type")
		}
		elems := make([]string, len(e.Elts))
		for i, el := range e.Elts {
			if _, ok := el.(*ast.KeyValueExpr); ok {
				f.t.errf(el.Pos(), "keyed composite literals are not supported")
			}
			elems[i] = f.atom(el, k.elem())
		}
		return "[" + strings.Join(elems, ", ") + "]", false
	case *ast.BinaryExpr:
		if !f.kindOf(e.X).goInt {
			f.t.errf(e.Pos(), "arithmetic on Variables must go through the api")
		}
		gi := kind{goInt: true}
		x, y := f.atom(e.X, gi), f.atom(e.Y, gi)
		switch e.Op {
		case token.ADD:
			return fmt.Sprintf("%s + %s", x, y), false
		case token.SUB:
			return fmt.Sprintf("%s - %s", x, y), false
		case token.MUL:
			return fmt.Sprintf("%s * %s", x, y), false
		case token.QUO:
			// Int64 division is Go's: truncation toward zero.
			return fmt.Sprintf("%s / %s", x, y), false
		case token.REM:
			// Int64 remainder is Go's: sign of the dividend.
			return fmt.Sprintf("%s %% %s", x, y), false
		default:
			f.t.errf(e.Pos(), "unsupported integer operator %s", e.Op)
		}
	}
	f.t.errf(e.Pos(), "unsupported expression %T", e)
	return "", false
}

func (f *funcTr) renderConst(v constant.Value, want kind, pos token.Pos) string {
	if v.Kind() != constant.Int {
		f.t.errf(pos, "unsupported constant %s", v)
	}
	s := v.ExactString()
	if want.goInt {
		// Bare numerals elaborate against the expected Int64 type;
		// let-bindings get an explicit ascription instead.
		return s
	}
	return fmt.Sprintf("(%s : F)", s)
}

// natRaw translates a Go integer expression used where Lean expects a Nat
// (indices, lengths, bit counts): constants render as numerals, everything
// else crosses the boundary through .toInt.toNat (clamping negatives to 0,
// where Go panics instead).
func (f *funcTr) natRaw(e ast.Expr) string {
	if tv, ok := f.info().Types[e]; ok && tv.Value != nil {
		if tv.Value.Kind() != constant.Int {
			f.t.errf(e.Pos(), "unsupported constant %s", tv.Value)
		}
		s := tv.Value.ExactString()
		if strings.HasPrefix(s, "-") {
			f.t.errf(e.Pos(), "constant negative index or size")
		}
		return s
	}
	// len(xs) used as a size is already a Nat; skip the Int64 round-trip.
	if call, ok := unparen(e).(*ast.CallExpr); ok {
		if id, ok := unparen(call.Fun).(*ast.Ident); ok {
			if b, ok := f.info().Uses[id].(*types.Builtin); ok && b.Name() == "len" {
				return f.atom(call.Args[0], f.kindOf(call.Args[0])) + ".length"
			}
		}
	}
	return f.atom(e, kind{goInt: true}) + ".toInt.toNat"
}

func (f *funcTr) natAtom(e ast.Expr) string {
	return wrapParen(f.natRaw(e))
}

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

func (f *funcTr) callee(call *ast.CallExpr) types.Object {
	switch fun := unparen(call.Fun).(type) {
	case *ast.Ident:
		return f.info().Uses[fun]
	case *ast.SelectorExpr:
		return f.info().Uses[fun.Sel]
	}
	return nil
}

func (f *funcTr) call(e *ast.CallExpr, want kind) (string, bool) {
	// Type conversions (uint32(n), frontend.Variable(0), ...) pass through.
	if tv, ok := f.info().Types[e.Fun]; ok && tv.IsType() {
		return f.exprTop(e.Args[0], f.t.classify(tv.Type, e.Pos()))
	}

	// Builtins.
	if id, ok := unparen(e.Fun).(*ast.Ident); ok {
		if b, ok := f.info().Uses[id].(*types.Builtin); ok {
			switch b.Name() {
			case "len":
				return "Int64.ofNat " + f.atom(e.Args[0], f.kindOf(e.Args[0])) + ".length", false
			case "append":
				bk := f.kindOf(e.Args[0])
				base := f.atom(e.Args[0], bk)
				if e.Ellipsis.IsValid() {
					return fmt.Sprintf("%s ++ %s", base, f.atom(e.Args[1], bk)), false
				}
				if len(e.Args) != 2 {
					f.t.errf(e.Pos(), "append with multiple elements is not supported")
				}
				return fmt.Sprintf("%s.concat %s", base, f.atom(e.Args[1], bk.elem())), false
			case "make":
				if len(e.Args) != 2 {
					f.t.errf(e.Pos(), "make requires an explicit length")
				}
				mk := f.t.classify(f.info().TypeOf(e), e.Pos())
				n := f.natAtom(e.Args[1])
				zero := "(0 : F)"
				if mk.depth > 1 {
					zero = "[]"
				}
				return fmt.Sprintf("List.replicate %s %s", n, zero), false
			default:
				f.t.errf(e.Pos(), "unsupported builtin %s", b.Name())
			}
		}
	}

	// api method calls become gates.
	if sel, ok := unparen(e.Fun).(*ast.SelectorExpr); ok {
		if id, ok := unparen(sel.X).(*ast.Ident); ok && f.api != nil && f.info().Uses[id] == f.api {
			return f.gate(sel.Sel.Name, e)
		}
	}

	// Static function calls: blackboxed or translated.
	fn, ok := f.callee(e).(*types.Func)
	if !ok {
		f.t.errf(e.Pos(), "unsupported call")
	}
	full := fn.Name()
	if fn.Pkg() != nil {
		full = fn.Pkg().Path() + "." + fn.Name()
	}
	if leanName, ok := f.t.cfg.Blackboxes[full]; ok {
		f.t.ensureAxiom(leanName, fn, e.Pos())
		return leanName + f.callArgs(e, fn), true
	}
	if fn.Pkg() == f.t.pkg.Types {
		name := f.t.translateFunc(fn, e.Pos())
		return name + f.callArgs(e, fn), true
	}
	f.t.errf(e.Pos(), "call to %s is not supported — register it as a blackbox", full)
	return "", false
}

// callArgs renders the arguments of a helper/blackbox call, dropping the
// frontend.API argument.
func (f *funcTr) callArgs(e *ast.CallExpr, fn *types.Func) string {
	sig := fn.Type().(*types.Signature)
	if sig.Variadic() {
		f.t.errf(e.Pos(), "variadic functions are not supported: %s", fn.Name())
	}
	var out strings.Builder
	for i, arg := range e.Args {
		pt := sig.Params().At(i).Type()
		if isAPI(pt) {
			continue
		}
		out.WriteString(" ")
		out.WriteString(f.atom(arg, f.t.classify(pt, arg.Pos())))
	}
	return out.String()
}

// gate translates a frontend.API method call.
func (f *funcTr) gate(name string, call *ast.CallExpr) (string, bool) {
	if call.Ellipsis.IsValid() && name != "FromBinary" {
		f.t.errf(call.Pos(), "spread arguments to api.%s are not supported", name)
	}
	arg := func(i int) string { return f.atom(call.Args[i], kind{}) }
	fold := func(op string) string {
		acc := fmt.Sprintf("Gates.%s %s %s", op, arg(0), arg(1))
		for i := 2; i < len(call.Args); i++ {
			acc = fmt.Sprintf("Gates.%s (%s) %s", op, acc, arg(i))
		}
		return acc
	}
	switch name {
	case "Add":
		return fold("add"), false
	case "Sub":
		return fold("sub"), false
	case "Mul":
		return fold("mul"), false
	case "Neg":
		return "Gates.neg " + arg(0), false
	case "Select":
		return fmt.Sprintf("Gates.select %s %s %s", arg(0), arg(1), arg(2)), false
	case "IsZero":
		return "Gates.isZero " + arg(0), false
	case "Xor":
		return fmt.Sprintf("Gates.xor %s %s", arg(0), arg(1)), false
	case "And":
		return fmt.Sprintf("Gates.and %s %s", arg(0), arg(1)), false
	case "Or":
		return fmt.Sprintf("Gates.or %s %s", arg(0), arg(1)), false
	case "Lookup2":
		return fmt.Sprintf("Gates.lookup2 %s %s %s %s %s %s",
			arg(0), arg(1), arg(2), arg(3), arg(4), arg(5)), false
	case "FromBinary":
		if call.Ellipsis.IsValid() {
			return "Gates.fromBinary " + f.atom(call.Args[0], kind{depth: 1}), false
		}
		var bits []string
		for i := range call.Args {
			bits = append(bits, f.atom(call.Args[i], kind{}))
		}
		return fmt.Sprintf("Gates.fromBinary [%s]", strings.Join(bits, ", ")), false
	case "Div":
		return fmt.Sprintf("Gates.div %s %s", arg(0), arg(1)), true
	case "DivUnchecked":
		return fmt.Sprintf("Gates.divUnchecked %s %s", arg(0), arg(1)), true
	case "Inverse":
		return "Gates.inv " + arg(0), true
	case "ToBinary":
		n := fmt.Sprintf("%d", f.t.cfg.Field.ScalarField().BitLen())
		if len(call.Args) == 2 {
			n = f.natAtom(call.Args[1])
		}
		return fmt.Sprintf("Gates.toBinary %s %s", arg(0), n), true
	case "AssertIsEqual":
		return fmt.Sprintf("Gates.eq %s %s", arg(0), arg(1)), true
	case "AssertIsDifferent":
		return fmt.Sprintf("Gates.ne %s %s", arg(0), arg(1)), true
	case "AssertIsBoolean":
		return "Gates.isBool " + arg(0), true
	case "AssertIsLessOrEqual":
		return fmt.Sprintf("Gates.le %s %s", arg(0), arg(1)), true
	}
	f.t.errf(call.Pos(), "unsupported api method %s", name)
	return "", false
}
