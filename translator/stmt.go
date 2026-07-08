package translator

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)

// block translates a statement list as one do-sequence, appending `pure ()`
// when the sequence would otherwise end in a binding. Loop and if bodies may
// end in a reassignment of a `mut` variable; function bodies may not.
func (b *funcBody) block(stmts []ast.Stmt, allowReassignEnd bool, prologue func()) {
	saved := b.last
	b.last = lastNone
	if prologue != nil {
		prologue()
	}
	for _, s := range stmts {
		b.stmt(s)
	}
	if b.last == lastNone || b.last == lastLet || (b.last == lastReassign && !allowReassignEnd) {
		b.emit("pure ()")
	}
	b.last = saved
}

func (b *funcBody) stmt(s ast.Stmt) {
	switch s := s.(type) {
	case *ast.BlockStmt:
		for _, st := range s.List {
			b.stmt(st)
		}
	case *ast.AssignStmt:
		b.assign(s)
	case *ast.ExprStmt:
		b.exprStmt(s)
	case *ast.ForStmt:
		b.forStmt(s)
	case *ast.RangeStmt:
		b.rangeStmt(s)
	case *ast.IfStmt:
		b.ifStmt(s)
	case *ast.ReturnStmt:
		b.returnStmt(s)
	case *ast.DeclStmt:
		b.declStmt(s)
	default:
		b.t.errf(s.Pos(), "unsupported statement %T", s)
	}
}

// declStmt handles `var x T` — zero-initialization of a local. For slice/
// array-typed locals we synthesize a `List.replicate n zero` binding;
// struct-typed locals bind to `default`. Anything else (int, F, without an
// initializer) is unusual enough to reject.
func (b *funcBody) declStmt(s *ast.DeclStmt) {
	gd, ok := s.Decl.(*ast.GenDecl)
	if !ok || gd.Tok != token.VAR {
		b.t.errf(s.Pos(), "unsupported declaration %T", s.Decl)
	}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			b.t.errf(spec.Pos(), "unsupported spec %T", spec)
		}
		if len(vs.Values) != 0 {
			b.t.errf(vs.Pos(), "var with initializer — use `:=` instead")
		}
		if vs.Type == nil {
			b.t.errf(vs.Pos(), "var without type")
		}
		typ := b.info().TypeOf(vs.Type)
		for _, id := range vs.Names {
			obj := b.info().Defs[id]
			k := b.t.classify(typ, id.Pos())
			name := b.bind(obj)
			mut := ""
			if b.muts[obj] {
				mut = "mut "
			}
			b.emit(fmt.Sprintf("let %s%s := %s", mut, name, b.t.zeroValueOf(k, typ, id.Pos())))
			b.last = lastLet
		}
	}
}

func (b *funcBody) assign(s *ast.AssignStmt) {
	if len(s.Lhs) > 1 && len(s.Rhs) == 1 {
		call, ok := unparen(s.Rhs[0]).(*ast.CallExpr)
		if !ok {
			b.t.errf(s.Pos(), "multi-assignment RHS must be a single call")
		}
		b.multiAssign(s, call)
		return
	}
	if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		b.t.errf(s.Pos(), "multi-assignment is not supported")
	}
	rhs := s.Rhs[0]
	switch s.Tok {
	case token.DEFINE:
		id, ok := s.Lhs[0].(*ast.Ident)
		if !ok {
			b.t.errf(s.Pos(), "unsupported := target")
		}
		if id.Name == "_" {
			b.discard(rhs)
			return
		}
		obj := b.info().Defs[id]
		k := b.t.classify(obj.Type(), id.Pos())
		b.aliasGuard(k, rhs)
		str, monadic := b.ec.exprTop(rhs, k)
		mut := ""
		if b.muts[obj] {
			mut = "mut "
		}
		// Ascribe Int64 bindings so bare numerals don't default to Nat.
		ascr := ""
		if k.goInt {
			ascr = " : Int64"
		}
		name := b.bind(obj)
		if monadic {
			b.emit(fmt.Sprintf("let %s%s%s ← %s", mut, name, ascr, str))
		} else {
			b.emit(fmt.Sprintf("let %s%s%s := %s", mut, name, ascr, str))
		}
		b.last = lastLet
	case token.ASSIGN:
		switch lhs := s.Lhs[0].(type) {
		case *ast.Ident:
			if lhs.Name == "_" {
				b.discard(rhs)
				return
			}
			obj := b.info().Uses[lhs]
			name, ok := b.names[obj]
			if !ok {
				b.t.errf(lhs.Pos(), "assignment to unknown variable %s", lhs.Name)
			}
			k := b.t.classify(obj.Type(), lhs.Pos())
			b.aliasGuard(k, rhs)
			str, monadic := b.ec.exprTop(rhs, k)
			if monadic {
				b.emit(fmt.Sprintf("%s ← %s", name, str))
			} else {
				b.emit(fmt.Sprintf("%s := %s", name, str))
			}
			b.last = lastReassign
		case *ast.IndexExpr:
			id, ok := lhs.X.(*ast.Ident)
			if !ok {
				b.t.errf(lhs.Pos(), "only simple `xs[i] = v` assignments are supported")
			}
			obj := b.info().Uses[id]
			name, ok := b.names[obj]
			if !ok {
				b.t.errf(lhs.Pos(), "assignment to unknown variable %s", id.Name)
			}
			bk := b.t.kindOf(lhs.X)
			idx := b.ec.natAtom(lhs.Index)
			val := b.ec.atom(rhs, bk.elem())
			b.emit(fmt.Sprintf("%s := %s.set %s %s", name, name, idx, val))
			b.last = lastReassign
		case *ast.SelectorExpr:
			// Struct field write on a local: rebind the local via Lean's
			// structure-update syntax `{ x with Field := v }`.
			id, ok := lhs.X.(*ast.Ident)
			if !ok {
				b.t.errf(lhs.Pos(), "field writes are only supported on a bound local")
			}
			obj := b.info().Uses[id]
			name, ok := b.names[obj]
			if !ok {
				b.t.errf(lhs.Pos(), "assignment to unknown variable %s", id.Name)
			}
			fieldName := sanitize(lhs.Sel.Name)
			fk := b.t.kindOf(lhs)
			val := b.ec.atom(rhs, fk)
			b.emit(fmt.Sprintf("%s := { %s with %s := %s }", name, name, fieldName, val))
			b.last = lastReassign
		default:
			b.t.errf(s.Pos(), "unsupported assignment target %T", lhs)
		}
	default:
		b.t.errf(s.Pos(), "unsupported assignment operator %s", s.Tok)
	}
}

// multiAssign translates `x, y := f(...)` (and the `(T, error)` variant
// `v, err := f(...)`), where the RHS is a single call. A trailing `error`
// result binds a Go-side plumbing variable that is never referenced from the
// Lean side; the remaining results either bind directly (single value) or
// through a tuple pattern.
func (b *funcBody) multiAssign(s *ast.AssignStmt, call *ast.CallExpr) {
	if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
		b.t.errf(s.Pos(), "unsupported multi-assignment operator %s", s.Tok)
	}
	reassign := s.Tok == token.ASSIGN
	fn, _ := b.t.callee(call).(*types.Func)
	if fn == nil {
		b.t.errf(s.Pos(), "multi-assignment from a call requires a static callee")
	}
	sig := fn.Type().(*types.Signature)
	if len(s.Lhs) != sig.Results().Len() {
		b.t.errf(s.Pos(), "LHS count %d does not match callee result count %d",
			len(s.Lhs), sig.Results().Len())
	}
	results, droppedErr := stripTrailingError(sig.Results())
	n := results.Len()

	str, monadic := b.ec.exprTop(call, kind{})
	if !monadic {
		b.t.errf(s.Pos(), "multi-assignment RHS must be a Circuit-valued call")
	}

	if droppedErr {
		errIdent, ok := s.Lhs[len(s.Lhs)-1].(*ast.Ident)
		if !ok {
			b.t.errf(s.Lhs[len(s.Lhs)-1].Pos(), "err position must be an identifier")
		}
		if errIdent.Name != "_" {
			obj := b.info().Defs[errIdent]
			if obj == nil {
				obj = b.info().Uses[errIdent]
			}
			if obj != nil {
				b.errVars[obj] = true
			}
		}
	}

	if n == 0 {
		b.emit("let _ ← " + str)
		b.last = lastLet
		return
	}

	// hasIndexLhs reports whether any tuple position is `xs[i] = ...`;
	// those go through a bind-then-set path below.
	hasIndexLhs := false
	for _, l := range s.Lhs {
		if _, ok := l.(*ast.IndexExpr); ok {
			hasIndexLhs = true
			break
		}
	}
	bindPos := func(i int) (name string, isBlank bool) {
		id, ok := s.Lhs[i].(*ast.Ident)
		if !ok {
			b.t.errf(s.Lhs[i].Pos(), "unsupported multi-assign target")
		}
		if id.Name == "_" {
			return "_", true
		}
		if reassign {
			obj := b.info().Uses[id]
			existing, ok := b.names[obj]
			if !ok {
				b.t.errf(id.Pos(), "reassignment to unknown variable %s", id.Name)
			}
			return existing, false
		}
		obj := b.info().Defs[id]
		if obj == nil {
			b.t.errf(id.Pos(), "%s must be a new binding here", id.Name)
		}
		return b.bind(obj), false
	}

	if n == 1 {
		name, blank := bindPos(0)
		if blank {
			b.emit("let _ ← " + str)
			b.last = lastLet
			return
		}
		if reassign {
			b.emit(fmt.Sprintf("%s ← %s", name, str))
			b.last = lastReassign
			return
		}
		k := b.t.classify(results.At(0).Type(), s.Pos())
		mut := ""
		if obj := b.info().Defs[s.Lhs[0].(*ast.Ident)]; obj != nil && b.muts[obj] {
			mut = "mut "
		}
		ascr := ""
		if k.goInt {
			ascr = " : Int64"
		}
		b.emit(fmt.Sprintf("let %s%s%s ← %s", mut, name, ascr, str))
		b.last = lastLet
		return
	}

	if hasIndexLhs {
		// Mixed / index-write LHS: bind the tuple to a fresh name, then
		// materialise each position as an ident-set or a slice `.set`.
		tmp := fmt.Sprintf("t_%d", b.tmp)
		b.tmp++
		b.emit(fmt.Sprintf("let %s ← %s", tmp, str))
		for i, lhs := range s.Lhs {
			switch l := lhs.(type) {
			case *ast.Ident:
				if l.Name == "_" {
					continue
				}
				name, blank := bindPos(i)
				if blank {
					continue
				}
				if reassign {
					b.emit(fmt.Sprintf("%s := %s.%d", name, tmp, i+1))
				} else {
					b.emit(fmt.Sprintf("let %s := %s.%d", name, tmp, i+1))
				}
			case *ast.IndexExpr:
				id, ok := l.X.(*ast.Ident)
				if !ok {
					b.t.errf(l.Pos(), "only simple `xs[i]` targets are supported in multi-assign")
				}
				obj := b.info().Uses[id]
				name, ok := b.names[obj]
				if !ok {
					b.t.errf(l.Pos(), "assignment to unknown variable %s", id.Name)
				}
				b.emit(fmt.Sprintf("%s := %s.set %s (%s.%d)", name, name, b.ec.natAtom(l.Index), tmp, i+1))
			default:
				b.t.errf(lhs.Pos(), "unsupported multi-assign target %T", lhs)
			}
		}
		b.last = lastReassign
		return
	}
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i], _ = bindPos(i)
	}
	if reassign {
		// Lean has no built-in `(x, y) ← m` destructure for reassignment;
		// bind the tuple to a fresh name and pull each field out.
		tmp := fmt.Sprintf("t_%d", b.tmp)
		b.tmp++
		b.emit(fmt.Sprintf("let %s ← %s", tmp, str))
		for i, p := range parts {
			b.emit(fmt.Sprintf("%s := %s.%d", p, tmp, i+1))
		}
		b.last = lastReassign
		return
	}
	b.emit(fmt.Sprintf("let (%s) ← %s", strings.Join(parts, ", "), str))
	b.last = lastLet
}

// discard translates `_ = e` / `_ := e`.
func (b *funcBody) discard(rhs ast.Expr) {
	str, monadic := b.discardExpr(rhs)
	if monadic {
		b.emit("let _ ← " + str)
	} else {
		b.emit("let _ := " + str)
	}
	b.last = lastLet
}

func (b *funcBody) exprStmt(s *ast.ExprStmt) {
	call, ok := s.X.(*ast.CallExpr)
	if !ok {
		b.t.errf(s.Pos(), "unsupported expression statement")
	}
	// Bare `copy(dst, src)`: value-semantic rebind of dst; discard the count.
	if id, ok := unparen(call.Fun).(*ast.Ident); ok {
		if bi, ok := b.info().Uses[id].(*types.Builtin); ok && bi.Name() == "copy" {
			b.emitCopy(call)
			return
		}
	}
	str, monadic := b.discardExpr(call)
	switch {
	case monadic && b.callIsUnit(call):
		b.emit(str)
		b.last = lastExpr
	case monadic:
		b.emit("let _ ← " + str)
		b.last = lastLet
	default:
		b.emit("let _ := " + str)
		b.last = lastLet
	}
}

// emitCopy translates Go's `copy(dst, src)` under value semantics: it rebinds
// dst so it holds the appropriate prefix of src. Two dst shapes are
// supported — a bound ident (`copy(xs, src)`) and a slice expression on a
// bound ident (`copy(xs[a:b], src)`), which splices src into the range.
func (b *funcBody) emitCopy(call *ast.CallExpr) {
	if len(call.Args) != 2 {
		b.t.errf(call.Pos(), "copy expects two arguments")
	}
	dstExpr := unparen(call.Args[0])
	src := b.ec.atom(call.Args[1], b.t.kindOf(call.Args[1]))

	switch dst := dstExpr.(type) {
	case *ast.Ident:
		obj := b.info().Uses[dst]
		name, ok := b.names[obj]
		if !ok {
			b.t.errf(dst.Pos(), "copy target is not a bound variable")
		}
		b.emit(fmt.Sprintf("%s := %s.take %s.length", name, src, name))
	case *ast.SliceExpr:
		if dst.Slice3 {
			b.t.errf(dst.Pos(), "three-index slice in copy target")
		}
		id, ok := unparen(dst.X).(*ast.Ident)
		if !ok {
			b.t.errf(dst.Pos(), "copy target must be a slice of a bound variable")
		}
		obj := b.info().Uses[id]
		name, ok := b.names[obj]
		if !ok {
			b.t.errf(id.Pos(), "copy target is not a bound variable")
		}
		lo := "0"
		if dst.Low != nil {
			lo = b.ec.natAtom(dst.Low)
		}
		hi := name + ".length"
		if dst.High != nil {
			hi = b.ec.natAtom(dst.High)
		}
		b.emit(fmt.Sprintf("%s := %s.take %s ++ %s.take (%s - %s) ++ %s.drop %s",
			name, name, lo, src, hi, lo, name, hi))
	default:
		b.t.errf(dstExpr.Pos(), "copy destination must be a variable or a slice expression")
	}
	b.last = lastReassign
}

// callIsUnit reports whether a call produces no value (assertions, void
// helpers), so it can stand alone as a do-statement.
func (b *funcBody) callIsUnit(call *ast.CallExpr) bool {
	if sel, ok := unparen(call.Fun).(*ast.SelectorExpr); ok {
		if id, ok := unparen(sel.X).(*ast.Ident); ok && b.api != nil && b.info().Uses[id] == b.api {
			switch sel.Sel.Name {
			case "AssertIsEqual", "AssertIsDifferent", "AssertIsBoolean", "AssertIsLessOrEqual":
				return true
			}
			return false
		}
	}
	if fn, ok := b.t.callee(call).(*types.Func); ok {
		// abstractor.Call/CallVoid/Call1/... are rewritten to the
		// gadget's DefineGadget, whose Lean return type isn't Unit
		// (even for CallVoid). Always discard-bind at statement level.
		if isAbstractorCallVariant(fn) {
			return false
		}
		return fn.Type().(*types.Signature).Results().Len() == 0
	}
	return false
}

func (b *funcBody) forStmt(s *ast.ForStmt) {
	init, ok := s.Init.(*ast.AssignStmt)
	if !ok || init.Tok != token.DEFINE || len(init.Lhs) != 1 {
		b.t.errf(s.Pos(), "only `for i := lo; i < hi; i++` loops are supported")
	}
	id := init.Lhs[0].(*ast.Ident)
	obj := b.info().Defs[id]
	cond, ok := s.Cond.(*ast.BinaryExpr)
	if !ok || cond.Op != token.LSS {
		b.t.errf(s.Pos(), "only `i < hi` loop conditions are supported")
	}
	if cid, ok := unparen(cond.X).(*ast.Ident); !ok || b.info().Uses[cid] != obj {
		b.t.errf(s.Pos(), "loop condition must test the loop variable")
	}
	post, ok := s.Post.(*ast.IncDecStmt)
	if !ok || post.Tok != token.INC {
		b.t.errf(s.Pos(), "only `i++` loop increments are supported")
	}
	// Go re-evaluates the bound every iteration; the translation evaluates it
	// once at loop entry. Reject bodies that reassign what the bound reads.
	// Element writes are fine: they cannot change a length.
	b.forbidBodyAssign(s.Body, b.readVars(cond.Y), false,
		"which the loop bound reads — Go re-evaluates the bound every iteration, the translation does not")
	lo := b.ec.atom(init.Rhs[0], kind{goInt: true})
	hi := b.ec.atom(cond.Y, kind{goInt: true})
	name := b.bind(obj)
	b.emit(fmt.Sprintf("for %s in goRange %s %s do", name, lo, hi))
	b.indent++
	b.block(s.Body.List, true, nil)
	b.indent--
	b.last = lastExpr
}

func (b *funcBody) rangeStmt(s *ast.RangeStmt) {
	if s.Key == nil {
		b.t.errf(s.Pos(), "`for range` without variables is not supported")
	}
	if s.Tok != token.DEFINE {
		b.t.errf(s.Pos(), "only `for i, v := range` loops are supported")
	}
	xk := b.t.kindOf(s.X)
	if xk.goInt || xk.depth < 1 {
		b.t.errf(s.X.Pos(), "range is only supported over slices/arrays of Variable")
	}
	if xk.depth > 1 && s.Value != nil {
		b.t.errf(s.Value.Pos(), "ranging with a value over nested slices aliases the inner slices")
	}
	xs := b.ec.atom(s.X, xk)

	keyId, _ := s.Key.(*ast.Ident)
	var valId *ast.Ident
	if s.Value != nil {
		valId, _ = s.Value.(*ast.Ident)
		if valId != nil && valId.Name == "_" {
			valId = nil
		}
	}
	// The Go/translation semantic divergence is: Go captures the backing
	// array at loop entry, the translation reads the ranged variable
	// afresh each iteration. Reassigning the ranged variable is always
	// unsafe; writing its elements matters only when a value binding is
	// present (that binding is what would see the shifted contents).
	b.forbidBodyAssign(s.Body, b.readVars(s.X), valId != nil,
		"which is being ranged over — Go iterates the backing array captured at loop entry")

	if keyId.Name == "_" && valId != nil {
		// `for _, v := range xs` iterates directly.
		vname := b.bind(b.info().Defs[valId])
		b.emit(fmt.Sprintf("for %s in %s do", vname, xs))
		b.indent++
		b.block(s.Body.List, true, nil)
		b.indent--
		b.last = lastExpr
		return
	}

	iname := b.bind(b.info().Defs[keyId])
	b.emit(fmt.Sprintf("for %s in goRange 0 (Int64.ofNat %s.length) do", iname, xs))
	b.indent++
	var prologue func()
	if valId != nil {
		vname := b.bind(b.info().Defs[valId])
		prologue = func() {
			b.emit(fmt.Sprintf("let %s := %s[%s.toInt.toNat]!", vname, xs, iname))
			b.last = lastLet
		}
	}
	b.block(s.Body.List, true, prologue)
	b.indent--
	b.last = lastExpr
}

// isErrCheck matches the `if err != nil { return ... }` guard that surrounds
// a `v, err := f(...)` call to a `(T, error)` helper. The whole block is Go-
// side plumbing — the translator drops it and continues on the success path.
func (b *funcBody) isErrCheck(s *ast.IfStmt) bool {
	if s.Init != nil || s.Else != nil {
		return false
	}
	be, ok := s.Cond.(*ast.BinaryExpr)
	if !ok || be.Op != token.NEQ {
		return false
	}
	var errIdent *ast.Ident
	switch {
	case isNilIdent(be.Y):
		errIdent, _ = unparen(be.X).(*ast.Ident)
	case isNilIdent(be.X):
		errIdent, _ = unparen(be.Y).(*ast.Ident)
	}
	if errIdent == nil {
		return false
	}
	obj := b.info().Uses[errIdent]
	if obj == nil || !b.errVars[obj] {
		return false
	}
	if len(s.Body.List) != 1 {
		return false
	}
	_, ok = s.Body.List[0].(*ast.ReturnStmt)
	return ok
}

func isNilIdent(e ast.Expr) bool {
	id, ok := unparen(e).(*ast.Ident)
	return ok && id.Name == "nil"
}

// initErrCheck matches the init-form err guard:
//
//	if err := f(...); err != nil { return err|nil }
//
// which is Go-side plumbing wrapped around a single call. The call itself
// still needs its side effects — if f is a helper that takes frontend.API
// (a circuit-level helper), it's translated as `let _ ← f …`; if not
// (pure-Go validation like `validateLayout`), the whole block is dropped.
// Returns (handled, dropWholeBlock). If handled is false the caller falls
// through to the generic if handling.
func (b *funcBody) initErrCheck(s *ast.IfStmt) (bool, *ast.CallExpr) {
	if s.Init == nil || s.Else != nil {
		return false, nil
	}
	as, ok := s.Init.(*ast.AssignStmt)
	if !ok || as.Tok != token.DEFINE || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return false, nil
	}
	errIdent, ok := as.Lhs[0].(*ast.Ident)
	if !ok || errIdent.Name != "err" {
		return false, nil
	}
	call, ok := unparen(as.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return false, nil
	}
	fn, ok := b.t.callee(call).(*types.Func)
	if fn == nil || !ok {
		return false, nil
	}
	sig := fn.Type().(*types.Signature)
	if sig.Results().Len() != 1 || !isError(sig.Results().At(0).Type()) {
		return false, nil
	}
	be, ok := s.Cond.(*ast.BinaryExpr)
	if !ok || be.Op != token.NEQ {
		return false, nil
	}
	var checkIdent *ast.Ident
	switch {
	case isNilIdent(be.Y):
		checkIdent, _ = unparen(be.X).(*ast.Ident)
	case isNilIdent(be.X):
		checkIdent, _ = unparen(be.Y).(*ast.Ident)
	}
	if checkIdent == nil || checkIdent.Name != "err" {
		return false, nil
	}
	if len(s.Body.List) != 1 {
		return false, nil
	}
	if _, ok := s.Body.List[0].(*ast.ReturnStmt); !ok {
		return false, nil
	}
	return true, call
}

func (b *funcBody) ifStmt(s *ast.IfStmt) {
	if b.isErrCheck(s) {
		return
	}
	if handled, call := b.initErrCheck(s); handled {
		// If the guarded call takes an api parameter, translate it as a
		// discard so its circuit side effects still land; otherwise it's
		// pure Go plumbing (e.g. `validateLayout`) and the whole if is
		// dropped.
		fn := b.t.callee(call).(*types.Func)
		sig := fn.Type().(*types.Signature)
		takesAPI := false
		for i := 0; i < sig.Params().Len(); i++ {
			if isAPI(sig.Params().At(i).Type()) {
				takesAPI = true
				break
			}
		}
		if takesAPI {
			str, monadic := b.discardExpr(call)
			if monadic {
				b.emit("let _ ← " + str)
			} else {
				b.emit("let _ := " + str)
			}
			b.last = lastLet
		}
		return
	}
	if s.Init != nil {
		b.t.errf(s.Pos(), "if statements with init clauses are not supported")
	}
	b.emit(fmt.Sprintf("if %s then", b.cond(s.Cond)))
	b.indent++
	b.block(s.Body.List, true, nil)
	b.indent--
	if s.Else != nil {
		els, ok := s.Else.(*ast.BlockStmt)
		if !ok {
			b.t.errf(s.Else.Pos(), "else-if chains are not supported")
		}
		b.emit("else")
		b.indent++
		b.block(els.List, true, nil)
		b.indent--
	}
	b.last = lastExpr
}

// cond translates a Go-level (size/config) boolean expression into a Lean
// decidable proposition (or a Bool for goBool-valued expressions like
// helper params of type Go `bool`).
func (b *funcBody) cond(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return b.cond(e.X)
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return "!" + wrapParen(b.cond(e.X))
		}
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND:
			return fmt.Sprintf("(%s ∧ %s)", b.cond(e.X), b.cond(e.Y))
		case token.LOR:
			return fmt.Sprintf("(%s ∨ %s)", b.cond(e.X), b.cond(e.Y))
		}
		if !b.t.kindOf(e.X).goInt {
			b.t.errf(e.Pos(), "conditions may only compare Go integers")
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
			b.t.errf(e.Pos(), "unsupported condition operator %s", e.Op)
		}
		return fmt.Sprintf("%s %s %s", b.ec.atom(e.X, kind{goInt: true}), op, b.ec.atom(e.Y, kind{goInt: true}))
	}
	// Fall-through: expression must be Bool-valued (e.g. `s.zone`).
	if b.t.kindOf(e).goBool {
		s, _ := b.ec.exprBare(e, kind{goBool: true})
		return s
	}
	b.t.errf(e.Pos(), "unsupported condition %T", e)
	return ""
}

func (b *funcBody) returnStmt(s *ast.ReturnStmt) {
	if b.isMain {
		// Define returns error; only `return nil` is supported.
		if len(s.Results) != 1 || !b.info().Types[s.Results[0]].IsNil() {
			b.t.errf(s.Pos(), "Define may only `return nil`")
		}
		return
	}
	if len(s.Results) == 0 {
		// Bare `return` — either Unit (no result) or a return of the
		// named return values in their current state.
		if len(b.namedReturns) > 0 {
			if len(b.namedReturns) == 1 {
				b.emit("return " + b.namedReturns[0])
			} else {
				b.emit("return (" + strings.Join(b.namedReturns, ", ") + ")")
			}
			b.last = lastExpr
			return
		}
		b.emit("pure ()")
		b.last = lastExpr
		return
	}
	results := s.Results
	// A `(T, error)`-returning helper carries the error slot only on the Go
	// side. If the return statement supplies it, drop it here.
	if b.hasErrResult && len(results) == len(b.result)+1 {
		results = results[:len(results)-1]
	}
	if len(b.result) == 0 {
		if len(results) == 0 {
			b.emit("pure ()")
			b.last = lastExpr
			return
		}
		b.t.errf(s.Pos(), "unexpected return value")
	}
	if len(results) != len(b.result) {
		b.t.errf(s.Pos(), "return count mismatch: got %d, want %d", len(results), len(b.result))
	}
	if len(b.result) == 1 {
		str, monadic := b.ec.exprTop(results[0], b.result[0])
		if monadic {
			b.emit(str)
		} else {
			b.emit("return " + str)
		}
		b.last = lastExpr
		return
	}
	parts := make([]string, len(results))
	for i, r := range results {
		parts[i] = b.ec.atom(r, b.result[i])
	}
	b.emit("return (" + strings.Join(parts, ", ") + ")")
	b.last = lastExpr
}
