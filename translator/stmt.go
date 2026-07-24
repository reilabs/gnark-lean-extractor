package translator

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)

// block walks a top-level statement list into the current block level
// (b.stmts) with the given prologue running first. Loop / if bodies use
// collectBlock instead, which splices into a fresh child block. Terminator
// emission (`pure ()` when the last statement isn't a valid trailing form)
// happens later in renderBlock, which sees the final tree — not here.
func (b *funcBody) block(stmts []ast.Stmt, prologue func()) {
	if prologue != nil {
		prologue()
	}
	for _, s := range stmts {
		b.stmt(s)
	}
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
		b.errf(s.Pos(), "unsupported statement %T", s)
	}
}

// declStmt handles `var x T` — zero-initialization of a local. For slice/
// array-typed locals we synthesize a `List.replicate n zero` binding;
// struct-typed locals bind to `default`. Anything else (int, F, without an
// initializer) is unusual enough to reject.
func (b *funcBody) declStmt(s *ast.DeclStmt) {
	gd, ok := s.Decl.(*ast.GenDecl)
	if !ok || gd.Tok != token.VAR {
		b.errf(s.Pos(), "unsupported declaration %T", s.Decl)
	}
	for _, spec := range gd.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok {
			b.errf(spec.Pos(), "unsupported spec %T", spec)
		}
		if vs.Type == nil {
			b.errf(vs.Pos(), "var without type")
		}
		typ := b.info.TypeOf(vs.Type)
		// `var x T = v` — equivalent to `x := v` with an explicit type,
		// so walk each initializer at the declared kind. `var x T` (no
		// initializer) falls through to the zero-init path below.
		if len(vs.Values) != 0 {
			if len(vs.Values) != len(vs.Names) {
				b.errf(vs.Pos(), "var initializer count does not match name count")
			}
			for i, id := range vs.Names {
				obj := b.info.Defs[id]
				k := b.classify(typ, id.Pos())
				rhs := vs.Values[i]
				b.aliasGuard(k, rhs)
				str, monadic := b.exprTop(rhs, k)
				ascr := ""
				if k.base == baseInt64 {
					ascr = " : Int64"
				}
				name := b.bind(obj)
				b.push(letBind{name: name, ascr: ascr, rhs: str, monadic: monadic, mut: b.muts[obj]})
			}
			continue
		}
		for _, id := range vs.Names {
			obj := b.info.Defs[id]
			k := b.classify(typ, id.Pos())
			name := b.bind(obj)
			b.push(letBind{
				name: name,
				rhs:  b.zero(k, typ),
				mut:  b.muts[obj],
			})
		}
	}
}

func (b *funcBody) assign(s *ast.AssignStmt) {
	if len(s.Lhs) > 1 && len(s.Rhs) == 1 {
		call, ok := unparen(s.Rhs[0]).(*ast.CallExpr)
		if !ok {
			b.errf(s.Pos(), "multi-assignment RHS must be a single call")
		}
		b.multiAssign(s, call)
		return
	}
	if len(s.Lhs) > 1 && len(s.Lhs) == len(s.Rhs) {
		b.parallelAssign(s)
		return
	}
	if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		b.errf(s.Pos(), "multi-assignment is not supported")
	}
	rhs := s.Rhs[0]
	switch s.Tok {
	case token.DEFINE:
		id, ok := s.Lhs[0].(*ast.Ident)
		if !ok {
			b.errf(s.Pos(), "unsupported := target")
		}
		if id.Name == "_" {
			b.discard(rhs)
			return
		}
		obj := b.info.Defs[id]
		k := b.classify(obj.Type(), id.Pos())
		b.aliasGuard(k, rhs)
		str, monadic := b.exprTop(rhs, k)
		// Ascribe Int64 bindings so bare numerals don't default to Nat.
		ascr := ""
		if k.base == baseInt64 {
			ascr = " : Int64"
		}
		name := b.bind(obj)
		b.push(letBind{name: name, ascr: ascr, rhs: str, monadic: monadic, mut: b.muts[obj]})
	case token.ASSIGN:
		switch lhs := s.Lhs[0].(type) {
		case *ast.Ident:
			if lhs.Name == "_" {
				b.discard(rhs)
				return
			}
			obj := b.info.Uses[lhs]
			name, ok := b.names[obj]
			if !ok {
				b.errf(lhs.Pos(), "assignment to unknown variable %s", lhs.Name)
			}
			k := b.classify(obj.Type(), lhs.Pos())
			b.aliasGuard(k, rhs)
			str, monadic := b.exprTop(rhs, k)
			b.push(reassign{name: name, rhs: str, monadic: monadic})
		case *ast.IndexExpr:
			id, ok := lhs.X.(*ast.Ident)
			if !ok {
				b.errf(lhs.Pos(), "only simple `xs[i] = v` assignments are supported")
			}
			obj := b.info.Uses[id]
			name, ok := b.names[obj]
			if !ok {
				b.errf(lhs.Pos(), "assignment to unknown variable %s", id.Name)
			}
			bk := b.kindOf(lhs.X)
			idx := b.natAtom(lhs.Index)
			val := b.atom(rhs, bk.elem())
			b.push(indexSet{name: name, idx: idx, val: val})
		case *ast.SelectorExpr:
			// Struct field write on a local: rebind the local via Lean's
			// structure-update syntax `{ x with Field := v }`.
			id, ok := lhs.X.(*ast.Ident)
			if !ok {
				b.errf(lhs.Pos(), "field writes are only supported on a bound local")
			}
			obj := b.info.Uses[id]
			name, ok := b.names[obj]
			if !ok {
				b.errf(lhs.Pos(), "assignment to unknown variable %s", id.Name)
			}
			fieldName := sanitize(lhs.Sel.Name)
			fk := b.kindOf(lhs)
			val := b.atom(rhs, fk)
			b.push(fieldSet{name: name, field: fieldName, val: val})
		default:
			b.errf(s.Pos(), "unsupported assignment target %T", lhs)
		}
	case token.ADD_ASSIGN, token.SUB_ASSIGN, token.MUL_ASSIGN, token.QUO_ASSIGN, token.REM_ASSIGN:
		b.compoundAssign(s)
	default:
		b.errf(s.Pos(), "unsupported assignment operator %s", s.Tok)
	}
}

// compoundAssign translates `x op= v` (integer +=, -=, *=, /=, %=) on a bound
// local as `x := x op v`. Used mainly by while-loop counters (`i += 4`).
func (b *funcBody) compoundAssign(s *ast.AssignStmt) {
	id, ok := s.Lhs[0].(*ast.Ident)
	if !ok {
		b.errf(s.Pos(), "compound assignment is only supported on a bound variable")
	}
	obj := b.info.Uses[id]
	name, ok := b.names[obj]
	if !ok {
		b.errf(id.Pos(), "compound assignment to unknown variable %s", id.Name)
	}
	if b.classify(obj.Type(), id.Pos()).base != baseInt64 {
		b.errf(s.Pos(), "compound assignment is only supported on Go integers")
	}
	op := map[token.Token]string{
		token.ADD_ASSIGN: "+", token.SUB_ASSIGN: "-", token.MUL_ASSIGN: "*",
		token.QUO_ASSIGN: "/", token.REM_ASSIGN: "%",
	}[s.Tok]
	rhs := b.atom(s.Rhs[0], kind{base: baseInt64})
	b.push(reassign{name: name, rhs: fmt.Sprintf("%s %s %s", name, op, rhs)})
}

// multiAssign translates `x, y := f(...)` (and the `(T, error)` variant
// `v, err := f(...)`), where the RHS is a single call. A trailing `error`
// result binds a Go-side plumbing variable that is never referenced from the
// Lean side; the remaining results either bind directly (single value) or
// through a tuple pattern.
func (b *funcBody) multiAssign(s *ast.AssignStmt, call *ast.CallExpr) {
	if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
		b.errf(s.Pos(), "unsupported multi-assignment operator %s", s.Tok)
	}
	isReassign := s.Tok == token.ASSIGN
	fn, _ := b.callee(call).(*types.Func)
	if fn == nil {
		b.errf(s.Pos(), "multi-assignment from a call requires a static callee")
	}
	sig := fn.Type().(*types.Signature)
	if len(s.Lhs) != sig.Results().Len() {
		b.errf(s.Pos(), "LHS count %d does not match callee result count %d",
			len(s.Lhs), sig.Results().Len())
	}
	results, droppedErr := stripTrailingError(sig.Results())
	n := results.Len()

	str, monadic := b.exprTop(call, kind{})
	if !monadic {
		b.errf(s.Pos(), "multi-assignment RHS must be a Circuit-valued call")
	}

	if droppedErr {
		errIdent, ok := s.Lhs[len(s.Lhs)-1].(*ast.Ident)
		if !ok {
			b.errf(s.Lhs[len(s.Lhs)-1].Pos(), "err position must be an identifier")
		}
		if errIdent.Name != "_" {
			obj := b.info.Defs[errIdent]
			if obj == nil {
				obj = b.info.Uses[errIdent]
			}
			if obj != nil {
				b.errVars[obj] = true
			}
		}
	}

	if n == 0 {
		b.push(discardBind{rhs: str, monadic: true})
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
			b.errf(s.Lhs[i].Pos(), "unsupported multi-assign target")
		}
		if id.Name == "_" {
			return "_", true
		}
		if isReassign {
			obj := b.info.Uses[id]
			existing, ok := b.names[obj]
			if !ok {
				b.errf(id.Pos(), "reassignment to unknown variable %s", id.Name)
			}
			return existing, false
		}
		obj := b.info.Defs[id]
		if obj == nil {
			b.errf(id.Pos(), "%s must be a new binding here", id.Name)
		}
		return b.bind(obj), false
	}

	if n == 1 {
		name, blank := bindPos(0)
		if blank {
			b.push(discardBind{rhs: str, monadic: true})
			return
		}
		if isReassign {
			b.push(reassign{name: name, rhs: str, monadic: true})
			return
		}
		k := b.classify(results.At(0).Type(), s.Pos())
		mut := false
		if obj := b.info.Defs[s.Lhs[0].(*ast.Ident)]; obj != nil && b.muts[obj] {
			mut = true
		}
		ascr := ""
		if k.base == baseInt64 {
			ascr = " : Int64"
		}
		b.push(letBind{name: name, ascr: ascr, rhs: str, monadic: true, mut: mut})
		return
	}

	if hasIndexLhs {
		// Mixed / index-write LHS: bind the tuple to a fresh name, then
		// materialise each position as an ident-set or a slice `.set`.
		tmp := fmt.Sprintf("t_%d", b.tmp)
		b.tmp++
		var parts []tuplePart
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
				pk := tuplePartAssign
				if !isReassign {
					pk = tuplePartLet
				}
				parts = append(parts, tuplePart{kind: pk, name: name, tupleIx: i + 1})
			case *ast.IndexExpr:
				id, ok := l.X.(*ast.Ident)
				if !ok {
					b.errf(l.Pos(), "only simple `xs[i]` targets are supported in multi-assign")
				}
				obj := b.info.Uses[id]
				name, ok := b.names[obj]
				if !ok {
					b.errf(l.Pos(), "assignment to unknown variable %s", id.Name)
				}
				parts = append(parts, tuplePart{
					kind:    tuplePartIndex,
					name:    name,
					tupleIx: i + 1,
					idxExpr: b.natAtom(l.Index),
				})
			default:
				b.errf(lhs.Pos(), "unsupported multi-assign target %T", lhs)
			}
		}
		b.push(tupleAssign{tmp: tmp, rhs: str, parts: parts, arity: n})
		return
	}
	names := make([]string, n)
	for i := 0; i < n; i++ {
		names[i], _ = bindPos(i)
	}
	if isReassign {
		// Lean has no built-in `(x, y) ← m` destructure for reassignment;
		// bind the tuple to a fresh name and pull each field out.
		tmp := fmt.Sprintf("t_%d", b.tmp)
		b.tmp++
		parts := make([]tuplePart, n)
		for i, name := range names {
			parts[i] = tuplePart{kind: tuplePartAssign, name: name, tupleIx: i + 1}
		}
		b.push(tupleAssign{tmp: tmp, rhs: str, parts: parts, arity: n})
		return
	}
	b.push(tupleLet{names: names, rhs: str})
}

// parallelAssign translates Go's parallel assignment `a, b, … = x, y, …`
func (b *funcBody) parallelAssign(s *ast.AssignStmt) {
	n := len(s.Lhs)
	rhsStrs := make([]string, n)
	for i := range s.Lhs {
		k := b.kindOf(s.Lhs[i])
		rhsStrs[i] = b.atom(s.Rhs[i], k)
	}
	tmp := fmt.Sprintf("t_%d", b.tmp)
	b.tmp++
	parts := make([]tuplePart, 0, n)
	for i, lhs := range s.Lhs {
		id, ok := lhs.(*ast.Ident)
		if !ok {
			b.errf(lhs.Pos(), "parallel-assignment targets must be identifiers")
		}
		if id.Name == "_" {
			continue
		}
		if s.Tok == token.DEFINE {
			parts = append(parts, tuplePart{kind: tuplePartLet, name: b.bind(b.info.Defs[id]), tupleIx: i + 1})
			continue
		}
		name, ok := b.names[b.info.Uses[id]]
		if !ok {
			b.errf(id.Pos(), "assignment to unknown variable %s", id.Name)
		}
		parts = append(parts, tuplePart{kind: tuplePartAssign, name: name, tupleIx: i + 1})
	}
	b.push(tupleAssign{tmp: tmp, rhs: "(" + strings.Join(rhsStrs, ", ") + ")", parts: parts, arity: n, pure: true})
}

// discard translates `_ = e` / `_ := e`.
func (b *funcBody) discard(rhs ast.Expr) {
	str, monadic := b.discardExpr(rhs)
	b.push(discardBind{rhs: str, monadic: monadic})
}

func (b *funcBody) exprStmt(s *ast.ExprStmt) {
	call, ok := s.X.(*ast.CallExpr)
	if !ok {
		b.errf(s.Pos(), "unsupported expression statement")
	}
	// Bare `copy(dst, src)`: value-semantic rebind of dst; discard the count.
	if id, ok := unparen(call.Fun).(*ast.Ident); ok {
		if bi, ok := b.info.Uses[id].(*types.Builtin); ok && bi.Name() == "copy" {
			b.emitCopy(call)
			return
		}
	}
	// `table.Insert(v)`: append to the List F modeling the lookup table.
	if fn, ok := b.callee(call).(*types.Func); ok && logderivOp(fn) == "Insert" {
		b.emitLogderivInsert(call)
		return
	}
	str, monadic := b.discardExpr(call)
	switch {
	case monadic && b.callIsUnit(call):
		b.push(bareExpr{rhs: str})
	default:
		b.push(discardBind{rhs: str, monadic: monadic})
	}
}

// emitCopy translates Go's `copy(dst, src)` under value semantics: it rebinds
// dst so it holds the appropriate prefix of src. Two dst shapes are
// supported — a bound ident (`copy(xs, src)`) and a slice expression on a
// bound ident (`copy(xs[a:b], src)`), which splices src into the range.
func (b *funcBody) emitCopy(call *ast.CallExpr) {
	if len(call.Args) != 2 {
		b.errf(call.Pos(), "copy expects two arguments")
	}
	dstExpr := unparen(call.Args[0])
	src := b.atom(call.Args[1], b.kindOf(call.Args[1]))

	switch dst := dstExpr.(type) {
	case *ast.Ident:
		obj := b.info.Uses[dst]
		name, ok := b.names[obj]
		if !ok {
			b.errf(dst.Pos(), "copy target is not a bound variable")
		}
		b.push(copyFull{name: name, src: src})
	case *ast.SliceExpr:
		if dst.Slice3 {
			b.errf(dst.Pos(), "three-index slice in copy target")
		}
		id, ok := unparen(dst.X).(*ast.Ident)
		if !ok {
			b.errf(dst.Pos(), "copy target must be a slice of a bound variable")
		}
		obj := b.info.Uses[id]
		name, ok := b.names[obj]
		if !ok {
			b.errf(id.Pos(), "copy target is not a bound variable")
		}
		lo := "0"
		if dst.Low != nil {
			lo = b.natAtom(dst.Low)
		}
		hi := name + ".length"
		if dst.High != nil {
			hi = b.natAtom(dst.High)
		}
		b.push(copySlice{name: name, lo: lo, hi: hi, src: src})
	default:
		b.errf(dstExpr.Pos(), "copy destination must be a variable or a slice expression")
	}
}

// callIsUnit reports whether a call produces no value (assertions, void
// helpers), so it can stand alone as a do-statement.
func (b *funcBody) callIsUnit(call *ast.CallExpr) bool {
	if sel, ok := unparen(call.Fun).(*ast.SelectorExpr); ok {
		if id, ok := unparen(sel.X).(*ast.Ident); ok && b.api != nil && b.info.Uses[id] == b.api {
			switch sel.Sel.Name {
			case "AssertIsEqual", "AssertIsDifferent", "AssertIsBoolean", "AssertIsLessOrEqual":
				return true
			}
			return false
		}
	}
	if fn, ok := b.callee(call).(*types.Func); ok {
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
	// C-style while loop: `for cond { … }` (no init/post). The counter is an
	// ordinary mutable local the body advances; see whileStmt.
	if s.Init == nil && s.Post == nil && s.Cond != nil {
		b.whileStmt(s)
		return
	}
	init, ok := s.Init.(*ast.AssignStmt)
	if !ok || init.Tok != token.DEFINE || len(init.Lhs) != 1 {
		b.errf(s.Pos(), "only `for i := lo; i < hi; i++` or `i += k` loops are supported")
	}
	id := init.Lhs[0].(*ast.Ident)
	obj := b.info.Defs[id]
	// Split the loop condition into a primary `i < hi` clause and an
	// optional residual predicate joined by `&&`.
	primary, residual := splitLoopCond(s.Cond)
	if primary == nil {
		b.errf(s.Pos(), "only `i < hi` (optionally `&& <cond>`) loop conditions are supported")
	}
	if cid, ok := unparen(primary.X).(*ast.Ident); !ok || b.info.Uses[cid] != obj {
		b.errf(s.Pos(), "loop condition must test the loop variable")
	}
	// Post-clause: `i++` (stride 1) or `i += <expr>` (arbitrary stride).
	// The stride variant walks the loop var via goRangeStep so runtime
	// values can be used (e.g. `offset += bytesPerFE`).
	var step string
	switch post := s.Post.(type) {
	case *ast.IncDecStmt:
		if post.Tok != token.INC {
			b.errf(s.Pos(), "only `i++` and `i += k` loop increments are supported")
		}
		if pid, ok := post.X.(*ast.Ident); !ok || b.info.Uses[pid] != obj {
			b.errf(s.Pos(), "loop increment must update the loop variable")
		}
	case *ast.AssignStmt:
		if post.Tok != token.ADD_ASSIGN || len(post.Lhs) != 1 || len(post.Rhs) != 1 {
			b.errf(s.Pos(), "only `i++` and `i += k` loop increments are supported")
		}
		if pid, ok := post.Lhs[0].(*ast.Ident); !ok || b.info.Uses[pid] != obj {
			b.errf(s.Pos(), "loop increment must update the loop variable")
		}
		step = b.atom(post.Rhs[0], kind{base: baseInt64})
	default:
		b.errf(s.Pos(), "only `i++` and `i += k` loop increments are supported")
	}
	// Go re-evaluates the bound (and takeWhile predicate) every iteration;
	// the translation captures both at loop entry. Reject bodies that
	// reassign what either reads. Element writes are fine.
	boundReads := b.readVars(primary.Y)
	if residual != nil {
		for k, v := range b.readVars(residual) {
			boundReads[k] = v
		}
	}
	b.forbidBodyAssign(s.Body, boundReads, false,
		"which the loop bound reads — Go re-evaluates the bound every iteration, the translation does not")
	lo := b.atom(init.Rhs[0], kind{base: baseInt64})
	hi := b.atom(primary.Y, kind{base: baseInt64})
	name := b.bind(obj)
	// Translate residual now that the loop var is in scope, so idents
	// referring to it resolve to `name`.
	var takeWhile string
	if residual != nil {
		takeWhile = b.cond(residual)
	}
	body := b.collectBlock(s.Body.List, true, nil)
	b.push(forLoop{name: name, lo: lo, hi: hi, step: step, takeWhile: takeWhile, body: body})
}

// whileStmt translates a C-style `for i < hi { … }` loop whose body advances
// the counter `i` by a fixed stride (`i += k` / `i++`).
func (b *funcBody) whileStmt(s *ast.ForStmt) {
	primary, residual := splitLoopCond(s.Cond)
	if primary == nil {
		b.errf(s.Pos(), "while loops must have condition `i < hi`")
	}
	if residual != nil {
		b.errf(s.Pos(), "compound while-loop conditions are not supported")
	}
	cid, ok := unparen(primary.X).(*ast.Ident)
	if !ok {
		b.errf(s.Pos(), "while condition must test a counter variable")
	}
	counter := b.info.Uses[cid]
	if _, ok := b.names[counter]; !ok {
		b.errf(cid.Pos(), "while counter %s is not a bound local", cid.Name)
	}
	step, ok := b.whileStride(s.Body, counter)
	if !ok {
		b.errf(s.Pos(),
			"unsupported while loop: the body must advance %s by exactly one `%s += k` (or `%s++`)",
			cid.Name, cid.Name, cid.Name)
	}
	// The bound is captured once at loop entry; reject bodies that reassign
	// what it reads (the counter itself is expected to advance, so exclude it).
	boundReads := b.readVars(primary.Y)
	delete(boundReads, counter)
	b.forbidBodyAssign(s.Body, boundReads, false,
		"which the loop bound reads — Go re-evaluates the bound every iteration, the translation captures it once")
	lo := b.atom(cid, kind{base: baseInt64})
	hi := b.atom(primary.Y, kind{base: baseInt64})
	body := b.collectBlock(s.Body.List, true, nil)
	b.push(forLoop{name: "_", lo: lo, hi: hi, step: step, body: body})
}

// whileStride finds the counter's advance in a while-loop body
func (b *funcBody) whileStride(body *ast.BlockStmt, counter types.Object) (string, bool) {
	isCounter := func(e ast.Expr) bool {
		id, ok := unparen(e).(*ast.Ident)
		return ok && b.info.Uses[id] == counter
	}
	var incr ast.Node
	count := 0
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.IncDecStmt:
			if isCounter(n.X) {
				count++
				incr = n
			}
		case *ast.AssignStmt:
			for _, l := range n.Lhs {
				if isCounter(l) {
					count++
					incr = n
				}
			}
		}
		return true
	})
	if count != 1 {
		return "", false
	}
	switch n := incr.(type) {
	case *ast.IncDecStmt:
		if n.Tok == token.INC {
			return "1", true
		}
	case *ast.AssignStmt:
		if n.Tok == token.ADD_ASSIGN && len(n.Lhs) == 1 {
			return b.atom(n.Rhs[0], kind{base: baseInt64}), true
		}
	}
	return "", false
}

// splitLoopCond peels an `i < hi && <rest>` condition into its `i < hi`
// primary comparison and the residual predicate, returning (primary, rest).
// A bare `i < hi` returns (primary, nil). Anything else returns (nil, nil).
func splitLoopCond(e ast.Expr) (*ast.BinaryExpr, ast.Expr) {
	be, ok := unparen(e).(*ast.BinaryExpr)
	if !ok {
		return nil, nil
	}
	if be.Op == token.LSS {
		return be, nil
	}
	if be.Op != token.LAND {
		return nil, nil
	}
	left, ok := unparen(be.X).(*ast.BinaryExpr)
	if !ok || left.Op != token.LSS {
		return nil, nil
	}
	return left, be.Y
}

func (b *funcBody) rangeStmt(s *ast.RangeStmt) {
	if s.Key == nil {
		b.errf(s.Pos(), "`for range` without variables is not supported")
	}
	if s.Tok != token.DEFINE {
		b.errf(s.Pos(), "only `for i, v := range` loops are supported")
	}
	xk := b.kindOf(s.X)
	if xk.base == baseInt64 || xk.depth < 1 {
		b.errf(s.X.Pos(), "range is only supported over slices/arrays of Variable")
	}
	if xk.depth > 1 && s.Value != nil {
		b.errf(s.Value.Pos(), "ranging with a value over nested slices aliases the inner slices")
	}
	xs := b.atom(s.X, xk)

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
		vname := b.bind(b.info.Defs[valId])
		body := b.collectBlock(s.Body.List, true, nil)
		b.push(forSlice{val: vname, xs: xs, body: body})
		return
	}

	iname := b.bind(b.info.Defs[keyId])
	// forIndexed's renderer prepends `let <val> := <xs>[<idx>.toInt.toNat]!`
	// to the body when val is non-empty, so we just bind the name here.
	vname := ""
	if valId != nil {
		vname = b.bind(b.info.Defs[valId])
	}
	body := b.collectBlock(s.Body.List, true, nil)
	b.push(forIndexed{idx: iname, val: vname, xs: xs, body: body})
}

// isErrCheck matches the `if err != nil { return ... }` (or `panic(err)`)
// guard that surrounds a `v, err := f(...)` call to a `(T, error)` helper.
// The whole block is Go-side plumbing — the translator drops it and
// continues on the success path.
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
	obj := b.info.Uses[errIdent]
	if obj == nil || !b.errVars[obj] {
		return false
	}
	if len(s.Body.List) != 1 {
		return false
	}
	switch body := s.Body.List[0].(type) {
	case *ast.ReturnStmt:
		return true
	case *ast.ExprStmt:
		if call, ok := body.X.(*ast.CallExpr); ok {
			if id, ok := unparen(call.Fun).(*ast.Ident); ok {
				if bi, ok := b.info.Uses[id].(*types.Builtin); ok && bi.Name() == "panic" {
					return true
				}
			}
		}
	}
	return false
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
	fn, ok := b.callee(call).(*types.Func)
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
		fn := b.callee(call).(*types.Func)
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
			b.push(discardBind{rhs: str, monadic: monadic})
		}
		return
	}
	if s.Init != nil {
		b.errf(s.Pos(), "if statements with init clauses are not supported")
	}
	then := b.collectBlock(s.Body.List, true, nil)
	var els *block
	if s.Else != nil {
		elsBlock, ok := s.Else.(*ast.BlockStmt)
		if !ok {
			b.errf(s.Else.Pos(), "else-if chains are not supported")
		}
		e := b.collectBlock(elsBlock.List, true, nil)
		els = &e
	}
	b.push(ifStmt{cond: b.cond(s.Cond), then: then, els: els})
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
		if b.kindOf(e.X).base != baseInt64 {
			b.errf(e.Pos(), "conditions may only compare Go integers")
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
			b.errf(e.Pos(), "unsupported condition operator %s", e.Op)
		}
		return fmt.Sprintf("%s %s %s", b.atom(e.X, kind{base: baseInt64}), op, b.atom(e.Y, kind{base: baseInt64}))
	}
	// Fall-through: expression must be Bool-valued (e.g. `s.zone`).
	if b.kindOf(e).base == baseBool {
		s, _ := b.exprBare(e, kind{base: baseBool})
		return s
	}
	b.errf(e.Pos(), "unsupported condition %T", e)
	return ""
}

func (b *funcBody) returnStmt(s *ast.ReturnStmt) {
	if b.isMain {
		// Define returns error; only `return nil` is supported.
		if len(s.Results) != 1 || !b.info.Types[s.Results[0]].IsNil() {
			b.errf(s.Pos(), "Define may only `return nil`")
		}
		return
	}
	if len(s.Results) == 0 {
		// Bare `return` — either Unit (no result) or a return of the
		// named return values in their current state.
		if len(b.namedReturns) > 0 {
			if len(b.namedReturns) == 1 {
				b.push(ret{val: b.namedReturns[0]})
			} else {
				b.push(ret{val: "(" + strings.Join(b.namedReturns, ", ") + ")"})
			}
			return
		}
		b.push(ret{unit: true})
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
			b.push(ret{unit: true})
			return
		}
		b.errf(s.Pos(), "unexpected return value")
	}
	if len(results) != len(b.result) {
		b.errf(s.Pos(), "return count mismatch: got %d, want %d", len(results), len(b.result))
	}
	if len(b.result) == 1 {
		str, monadic := b.exprTop(results[0], b.result[0])
		b.push(ret{val: str, monadic: monadic})
		return
	}
	parts := make([]string, len(results))
	for i, r := range results {
		parts[i] = b.atom(r, b.result[i])
	}
	b.push(ret{val: "(" + strings.Join(parts, ", ") + ")"})
}
