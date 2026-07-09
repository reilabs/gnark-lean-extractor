package translator

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
)

// The expression walker lives directly on *funcBody — see atom / exprTop /
// exprBare / natRaw / natAtom / call / callArgs / gate / structLit below.
// A funcBody with isPkgInit=true is used for folding package-var
// initializers (no locals, no api, no receiver, and liftMonadic errfs).

func (b *funcBody) kindOf(e ast.Expr) kind {
	return b.classify(b.info.TypeOf(e), e.Pos())
}

// renderConst renders a folded Go constant at the wanted Lean kind.
func (b *funcBody) renderConst(v constant.Value, want kind, pos token.Pos) string {
	if v.Kind() == constant.Bool {
		if constant.BoolVal(v) {
			return "true"
		}
		return "false"
	}
	if v.Kind() != constant.Int {
		b.errf(pos, "unsupported constant %s", v)
	}
	s := v.ExactString()
	switch want.base {
	case baseInt64:
		// Bare numerals elaborate against the expected Int64 type;
		// let-bindings get an explicit ascription instead.
		return s
	case baseBigInt:
		return fmt.Sprintf("(%s : Int)", s)
	}
	return fmt.Sprintf("(%s : F)", s)
}

// isIntValued reports whether e is a non-constant Go integer expression
// (constants render directly at the wanted type instead).
func (b *funcBody) isIntValued(e ast.Expr) bool {
	if tv, ok := b.info.Types[e]; ok && tv.Value != nil {
		return false
	}
	typ := b.info.TypeOf(e)
	if typ == nil {
		return false
	}
	basic, ok := typ.Underlying().(*types.Basic)
	if !ok || basic.Info()&types.IsInteger == 0 {
		return false
	}
	// byte / uint8 already crosses into F via the []byte classification —
	// no `.toInt` bridge is needed (and would fail since the value is F).
	return basic.Kind() != types.Uint8
}

// zero renders the Lean expression for Go's zero value at kind k. If typ is
// non-nil and its underlying type is a fixed-length Array, the returned
// expression is `List.replicate N <elem-zero>` — needed so `var xs [N]F`
// declarations translate to the right length. Pass nil when only the kind
// is known (named returns, tuple slots) or when a slice's `[]` empty result
// is what you want.
func (b *funcBody) zero(k kind, typ types.Type) string {
	if k.depth == 0 {
		switch k.base {
		case baseInt64:
			return "(0 : Int64)"
		case baseBigInt:
			return "(0 : Int)"
		case baseBool:
			return "false"
		case baseStruct, baseOpaque:
			return "default"
		default:
			return "(0 : F)"
		}
	}
	if typ != nil {
		if arr, ok := typ.Underlying().(*types.Array); ok {
			return fmt.Sprintf("List.replicate %d %s", arr.Len(), b.zero(k.elem(), arr.Elem()))
		}
	}
	return "[]"
}

func (b *funcBody) callee(call *ast.CallExpr) types.Object {
	fun := unparen(call.Fun)
	// Generic instantiations: `Fn[X]` and `Fn[X, Y]` show up in the AST as
	// IndexExpr / IndexListExpr wrapping the underlying callee. Peel that
	// layer so blackboxing by FQN still works.
	if idx, ok := fun.(*ast.IndexExpr); ok {
		fun = unparen(idx.X)
	}
	if idx, ok := fun.(*ast.IndexListExpr); ok {
		fun = unparen(idx.X)
	}
	switch fn := fun.(type) {
	case *ast.Ident:
		return b.info.Uses[fn]
	case *ast.SelectorExpr:
		return b.info.Uses[fn.Sel]
	}
	return nil
}

// atom translates an expression to a Lean term suitable for use as a
// function argument: monadic subexpressions are lifted via the scope,
// compound pure expressions are parenthesized.
func (b *funcBody) atom(e ast.Expr, want kind) string {
	str, monadic := b.exprTop(e, want)
	if monadic {
		return b.liftMonadic(str, e.Pos())
	}
	return wrapParen(str)
}

// exprTop translates e at the wanted kind, returning the Lean term and
// whether it is monadic. On top of exprBare, it inserts the implicit
// boundary coercions between the walker's output and the caller's want:
// Int64 → Int/F via `.toInt`, Int → F via ZMod's IntCast.
func (b *funcBody) exprTop(e ast.Expr, want kind) (string, bool) {
	str, monadic := b.exprBare(e, want)
	if monadic || want.depth != 0 {
		return str, monadic
	}
	// Int64-valued expression → the wanted target type.
	if b.isIntValued(e) {
		switch want.base {
		case baseInt64:
			// no coercion
		case baseBigInt:
			return fmt.Sprintf("(%s).toInt", str), false
		default:
			return fmt.Sprintf("((%s).toInt : F)", str), false
		}
	}
	// BigInt-classified expression → F wants a coercion.
	if want.base == baseF && b.kindOf(e).base == baseBigInt {
		return fmt.Sprintf("((%s) : F)", str), false
	}
	return str, false
}

// exprBare translates a Go expression to Lean, per-shape.
func (b *funcBody) exprBare(e ast.Expr, want kind) (string, bool) {
	if tv, ok := b.info.Types[e]; ok && tv.Value != nil {
		return b.renderConst(tv.Value, want, e.Pos()), false
	}
	switch e := e.(type) {
	case *ast.ParenExpr:
		return b.exprBare(e.X, want)
	case *ast.Ident:
		obj := b.info.Uses[e]
		if name, ok := b.resolveObj(obj, e.Pos()); ok {
			return name, false
		}
		// Package-level Var with a foldable initializer.
		if v, ok := obj.(*types.Var); ok && v.Parent() == b.pkg.Types.Scope() {
			return b.resolvePkgVar(v), false
		}
		b.errf(e.Pos(), "unknown identifier %s", e.Name)
	case *ast.SelectorExpr:
		sel, ok := b.info.Selections[e]
		if !ok || sel.Kind() != types.FieldVal {
			b.errf(e.Pos(), "unsupported selector expression")
		}
		// Circuit fields and named locals resolve directly.
		if name, ok := b.resolveObj(sel.Obj(), e.Pos()); ok {
			return name, false
		}
		// Nested field access: translate the base and append `.Field`.
		baseStr, monadic := b.exprBare(e.X, kind{})
		if monadic {
			b.errf(e.Pos(), "cannot select a field of a monadic expression")
		}
		return wrapParen(baseStr) + "." + sanitize(sel.Obj().Name()), false
	case *ast.IndexExpr:
		base := b.atom(e.X, b.kindOf(e.X))
		return fmt.Sprintf("%s[%s]!", base, b.natRaw(e.Index)), false
	case *ast.SliceExpr:
		if e.Slice3 {
			b.errf(e.Pos(), "three-index slice expressions are not supported")
		}
		base := b.atom(e.X, b.kindOf(e.X))
		// xs[:]       -> xs (identity)
		// xs[a:]      -> xs.drop a
		// xs[:b]      -> xs.take b
		// xs[a:b]     -> (xs.drop a).take (b - a)
		switch {
		case e.Low == nil && e.High == nil:
			return base, false
		case e.Low == nil:
			return fmt.Sprintf("%s.take %s", base, b.natAtom(e.High)), false
		case e.High == nil:
			return fmt.Sprintf("%s.drop %s", base, b.natAtom(e.Low)), false
		default:
			lo := b.natAtom(e.Low)
			hi := b.natAtom(e.High)
			return fmt.Sprintf("(%s.drop %s).take (%s - %s)", base, lo, hi, lo), false
		}
	case *ast.CallExpr:
		return b.call(e)
	case *ast.CompositeLit:
		k := b.classify(b.info.TypeOf(e), e.Pos())
		if k.base == baseStruct && k.depth == 0 {
			return b.structLit(e, k), false
		}
		if k.base == baseInt64 || k.depth == 0 {
			b.errf(e.Pos(), "unsupported composite literal type")
		}
		elems := make([]string, len(e.Elts))
		for i, el := range e.Elts {
			if _, ok := el.(*ast.KeyValueExpr); ok {
				b.errf(el.Pos(), "keyed composite literals are not supported")
			}
			elems[i] = b.atom(el, k.elem())
		}
		return "[" + strings.Join(elems, ", ") + "]", false
	case *ast.UnaryExpr:
		// `&x` is Go noise around passing a value struct/slice to a
		// helper. Erase the pointer op: the translation carries the value
		// through directly.
		if e.Op == token.AND {
			return b.exprBare(e.X, want)
		}
		// `!x` on Go bool → Lean Bool negation. Circuit-level `!` is
		// still routed through the gates path in cond().
		if e.Op == token.NOT {
			inner, monadic := b.exprBare(e.X, kind{base: baseBool})
			return "!" + wrapParen(inner), monadic
		}
		b.errf(e.Pos(), "unsupported unary operator %s", e.Op)
	case *ast.StarExpr:
		// `*p` — the dual of `&x`. Only accept when the operand is a
		// pointer to a value the translator already models (a value
		// receiver / by-value struct or slice), not e.g. a pointer field.
		if _, ok := b.info.TypeOf(e.X).(*types.Pointer); !ok {
			b.errf(e.Pos(), "cannot dereference non-pointer expression")
		}
		return b.exprBare(e.X, want)
	case *ast.BinaryExpr:
		if b.kindOf(e.X).base != baseInt64 {
			b.errf(e.Pos(), "arithmetic on Variables must go through the api")
		}
		gi := kind{base: baseInt64}
		x, y := b.atom(e.X, gi), b.atom(e.Y, gi)
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
		case token.SHL:
			return fmt.Sprintf("(Int64.shiftLeft (%s : Int64) %s)", x, y), false
		case token.SHR:
			return fmt.Sprintf("(Int64.shiftRight (%s : Int64) %s)", x, y), false
		default:
			b.errf(e.Pos(), "unsupported integer operator %s", e.Op)
		}
	}
	b.errf(e.Pos(), "unsupported expression %T", e)
	return "", false
}

// natRaw translates a Go integer expression used where Lean expects a Nat
// (indices, lengths, bit counts): constants render as numerals, everything
// else crosses the boundary through .toInt.toNat (clamping negatives to 0,
// where Go panics instead).
func (b *funcBody) natRaw(e ast.Expr) string {
	if tv, ok := b.info.Types[e]; ok && tv.Value != nil {
		if tv.Value.Kind() != constant.Int {
			b.errf(e.Pos(), "unsupported constant %s", tv.Value)
		}
		s := tv.Value.ExactString()
		if strings.HasPrefix(s, "-") {
			b.errf(e.Pos(), "constant negative index or size")
		}
		return s
	}
	// len(xs) used as a size is already a Nat; skip the Int64 round-trip.
	if call, ok := unparen(e).(*ast.CallExpr); ok {
		if id, ok := unparen(call.Fun).(*ast.Ident); ok {
			if bi, ok := b.info.Uses[id].(*types.Builtin); ok && bi.Name() == "len" {
				return b.atom(call.Args[0], b.kindOf(call.Args[0])) + ".length"
			}
		}
	}
	return b.atom(e, kind{base: baseInt64}) + ".toInt.toNat"
}

func (b *funcBody) natAtom(e ast.Expr) string {
	return wrapParen(b.natRaw(e))
}

func (b *funcBody) call(e *ast.CallExpr) (string, bool) {
	// Type conversions (uint32(n), frontend.Variable(0), ...) pass through.
	if tv, ok := b.info.Types[e.Fun]; ok && tv.IsType() {
		// []byte("...") — fold the string literal at translate time into
		// a `List F` of byte-wide numerals.
		if isByteSliceType(tv.Type) {
			if s, ok := stringLiteralValue(b.info, e.Args[0]); ok {
				parts := make([]string, len(s))
				for i := 0; i < len(s); i++ {
					parts[i] = fmt.Sprintf("(%d : F)", s[i])
				}
				return "[" + strings.Join(parts, ", ") + "]", false
			}
			b.errf(e.Pos(), "only string-literal []byte conversions are supported")
		}
		return b.exprTop(e.Args[0], b.classify(tv.Type, e.Pos()))
	}

	// Builtins.
	if id, ok := unparen(e.Fun).(*ast.Ident); ok {
		if bi, ok := b.info.Uses[id].(*types.Builtin); ok {
			switch bi.Name() {
			case "len":
				return "Int64.ofNat " + b.atom(e.Args[0], b.kindOf(e.Args[0])) + ".length", false
			case "append":
				bk := b.kindOf(e.Args[0])
				base := b.atom(e.Args[0], bk)
				if e.Ellipsis.IsValid() {
					return fmt.Sprintf("%s ++ %s", base, b.atom(e.Args[1], bk)), false
				}
				if len(e.Args) == 2 {
					return fmt.Sprintf("%s.concat %s", base, b.atom(e.Args[1], bk.elem())), false
				}
				// append(xs, a, b, ...): concat with a fresh list literal.
				elems := make([]string, len(e.Args)-1)
				for i, a := range e.Args[1:] {
					elems[i] = b.atom(a, bk.elem())
				}
				return fmt.Sprintf("%s ++ [%s]", base, strings.Join(elems, ", ")), false
			case "make":
				if len(e.Args) < 2 || len(e.Args) > 3 {
					b.errf(e.Pos(), "make requires a length (and optional capacity)")
				}
				mk := b.classify(b.info.TypeOf(e), e.Pos())
				n := b.natAtom(e.Args[1])
				return fmt.Sprintf("List.replicate %s %s", n, b.zero(mk.elem(), nil)), false
			case "panic":
				// Model panic as an unreachable Circuit
				return "Circuit.panic", true
			default:
				b.errf(e.Pos(), "unsupported builtin %s", bi.Name())
			}
		}
	}

	// api method calls become gates.
	if sel, ok := unparen(e.Fun).(*ast.SelectorExpr); ok {
		if id, ok := unparen(sel.X).(*ast.Ident); ok && b.isAPI(b.info.Uses[id]) {
			return b.gate(sel.Sel.Name, e)
		}
	}

	// Static function calls: blackboxed or translated.
	fn, ok := b.callee(e).(*types.Func)
	if !ok {
		b.errf(e.Pos(), "unsupported call")
	}
	full := fn.Name()
	if fn.Pkg() != nil {
		full = fn.Pkg().Path() + "." + fn.Name()
	}
	// abstractor.Call(api, X{...})   → X{...}.DefineGadget
	// abstractor.CallVoid(api, X{...}) → same, result discarded
	// abstractor.Call1/2/3            → same; wrapper's cast is elided
	// The DefineGadget method is translated by translateFunc when local
	// (its `interface{}` return type is inferred from the body); when the
	// gadget lives in a foreign package, it becomes an opaque axiom whose
	// output kind comes from the wrapper.
	if isAbstractorCallVariant(fn) {
		if len(e.Args) != 2 {
			b.errf(e.Pos(), "abstractor.%s expects (api, gadget)", fn.Name())
		}
		gadgetArg := e.Args[1]
		gadgetType := b.info.TypeOf(gadgetArg)
		method, _, _ := types.LookupFieldOrMethod(gadgetType, true, fn.Pkg(), "DefineGadget")
		defineFn, _ := method.(*types.Func)
		if defineFn == nil {
			b.errf(e.Pos(), "%s has no DefineGadget method", gadgetType)
		}
		gadgetStr := b.atom(gadgetArg, b.classify(gadgetType, e.Pos()))
		if _, walkable := b.pkgs[defineFn.Pkg()]; walkable {
			b.translateFunc(defineFn, e.Pos())
		} else {
			// Non-walkable gadget: axiomatize DefineGadget with the
			// wrapper's return kind. The gadget struct itself is already
			// registered by the classify call above.
			b.ensureGadgetAxiom(defineFn, gadgetType.(*types.Named), fn.Name(), e.Pos())
		}
		return gadgetStr + ".DefineGadget", true
	}
	// math/big specific implementations
	if str, ok := b.bigIntPeephole(e, fn); ok {
		return str, false
	}
	if leanName, ok := b.cfg.Blackboxes[full]; ok {
		actual := b.ensureAxiom(leanName, fn, e.Pos())
		return actual + b.callArgs(e, fn), true
	}
	if _, walkable := b.pkgs[fn.Pkg()]; walkable {
		name := b.translateFunc(fn, e.Pos())
		// For method calls, emit `<receiver>.<Method> <args>` dot syntax
		// (the receiver is the SelectorExpr base, not in call.Args).
		if fn.Type().(*types.Signature).Recv() != nil {
			sel, ok := unparen(e.Fun).(*ast.SelectorExpr)
			if !ok {
				b.errf(e.Pos(), "unexpected method call form")
			}
			recvStr := b.atom(sel.X, b.kindOf(sel.X))
			return recvStr + "." + fn.Name() + b.callArgs(e, fn), true
		}
		return name + b.callArgs(e, fn), true
	}
	b.errf(e.Pos(), "call to %s is not supported — register it as a blackbox", full)
	return "", false
}

// callArgs renders the arguments of a helper/blackbox call, dropping the
// frontend.API argument. Variadic callees are accepted in two shapes: the
// spread form `f(a, xs...)` — the ellipsis arg carries the whole slice —
// and the bundled form `f(a, b, c)` where the variadic tail is folded into
// a Lean list literal at the call site.
func (b *funcBody) callArgs(e *ast.CallExpr, fn *types.Func) string {
	sig := fn.Type().(*types.Signature)
	nParams := sig.Params().Len()
	variadic := sig.Variadic()
	// Fixed count for the non-variadic prefix.
	fixed := nParams
	if variadic {
		fixed = nParams - 1
	}
	var out strings.Builder
	// Emit the fixed prefix.
	for i := 0; i < fixed && i < len(e.Args); i++ {
		pt := sig.Params().At(i).Type()
		if isAPI(pt) {
			continue
		}
		out.WriteString(" ")
		out.WriteString(b.atom(e.Args[i], b.classify(pt, e.Args[i].Pos())))
	}
	if !variadic {
		return out.String()
	}
	// Variadic tail.
	sliceType, _ := sig.Params().At(nParams - 1).Type().(*types.Slice)
	var elemKind kind
	if sliceType != nil {
		elemKind = b.classify(sliceType.Elem(), e.Pos())
	}
	tail := e.Args[fixed:]
	if e.Ellipsis.IsValid() && len(tail) == 1 {
		// Spread: the caller already has a slice; pass through as-is.
		listKind := kind{base: elemKind.base, depth: elemKind.depth + 1, named: elemKind.named, opaque: elemKind.opaque}
		out.WriteString(" ")
		out.WriteString(b.atom(tail[0], listKind))
		return out.String()
	}
	// Bundle variadic args into a fresh list literal.
	parts := make([]string, len(tail))
	for i, a := range tail {
		parts[i] = b.atom(a, elemKind)
	}
	out.WriteString(" [")
	out.WriteString(strings.Join(parts, ", "))
	out.WriteString("]")
	return out.String()
}

// gate translates a frontend.API method call.
func (b *funcBody) gate(name string, call *ast.CallExpr) (string, bool) {
	if call.Ellipsis.IsValid() && name != "FromBinary" {
		b.errf(call.Pos(), "spread arguments to api.%s are not supported", name)
	}
	arg := func(i int) string { return b.atom(call.Args[i], kind{}) }
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
			return "Gates.fromBinary " + b.atom(call.Args[0], kind{depth: 1}), false
		}
		var bits []string
		for i := range call.Args {
			bits = append(bits, b.atom(call.Args[i], kind{}))
		}
		return fmt.Sprintf("Gates.fromBinary [%s]", strings.Join(bits, ", ")), false
	case "Div":
		return fmt.Sprintf("Gates.div %s %s", arg(0), arg(1)), true
	case "DivUnchecked":
		return fmt.Sprintf("Gates.divUnchecked %s %s", arg(0), arg(1)), true
	case "Inverse":
		return "Gates.inv " + arg(0), true
	case "ToBinary":
		n := fmt.Sprintf("%d", b.cfg.Field.ScalarField().BitLen())
		if len(call.Args) == 2 {
			n = b.natAtom(call.Args[1])
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
	b.errf(call.Pos(), "unsupported api method %s", name)
	return "", false
}

// synthesizeCircuitLiteral produces a Lean struct value for the Define
// receiver, so `circuit.method(...)` translates as a dot-syntax call on a
// synthesized record. Registers the Circuit type as a Lean structure on
// demand — nothing is emitted for circuits whose bodies never take the
// receiver's value.
func (b *funcBody) synthesizeCircuitLiteral(pos token.Pos) string {
	obj := b.mainPkg.Types.Scope().Lookup(b.cfg.Circuit)
	if obj == nil {
		b.errf(pos, "circuit type %s not found", b.cfg.Circuit)
	}
	named, ok := obj.Type().(*types.Named)
	if !ok {
		b.errf(pos, "circuit type %s is not a named struct", b.cfg.Circuit)
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		b.errf(pos, "circuit type %s is not a struct", b.cfg.Circuit)
	}
	b.classify(named, pos)
	structName := b.emit.structReg.name(named)
	parts := make([]string, st.NumFields())
	for i := 0; i < st.NumFields(); i++ {
		fld := st.Field(i)
		name := sanitize(fld.Name())
		parts[i] = fmt.Sprintf("%s := %s", name, name)
	}
	return fmt.Sprintf("({ %s : %s })", strings.Join(parts, ", "), structName)
}

// structLit renders a Go composite literal of a named-struct type as a
// Lean record. Both positional (`Utxo{a, b, c}`) and keyed
// (`Utxo{Owner: a}`) forms are supported; mixed forms match Go's rejection.
func (b *funcBody) structLit(e *ast.CompositeLit, k kind) string {
	st := k.named.Underlying().(*types.Struct)
	typName := b.emit.structReg.name(k.named)
	if len(e.Elts) == 0 {
		return fmt.Sprintf("({ : %s })", typName)
	}
	_, keyed := e.Elts[0].(*ast.KeyValueExpr)
	parts := make([]string, 0, st.NumFields())
	if keyed {
		// Go zero-initialises fields omitted from a keyed literal. Emit
		// each declared field in declaration order, taking the value from
		// the literal if present, `default` (via Inhabited) otherwise.
		supplied := make(map[string]ast.Expr, len(e.Elts))
		for _, el := range e.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				b.errf(el.Pos(), "mixed keyed/positional struct literal")
			}
			keyId, ok := kv.Key.(*ast.Ident)
			if !ok {
				b.errf(kv.Key.Pos(), "struct literal key must be a field name")
			}
			supplied[keyId.Name] = kv.Value
		}
		for i := 0; i < st.NumFields(); i++ {
			fld := st.Field(i)
			fk := b.classify(fld.Type(), e.Pos())
			var val string
			if v, ok := supplied[fld.Name()]; ok {
				val = b.atom(v, fk)
			} else {
				val = b.zero(fk, nil)
			}
			parts = append(parts, fmt.Sprintf("%s := %s", sanitize(fld.Name()), val))
		}
	} else {
		if len(e.Elts) != st.NumFields() {
			b.errf(e.Pos(), "positional struct literal must supply all fields of %s", typName)
		}
		for i, el := range e.Elts {
			fld := st.Field(i)
			fk := b.classify(fld.Type(), el.Pos())
			parts = append(parts, fmt.Sprintf("%s := %s", sanitize(fld.Name()), b.atom(el, fk)))
		}
	}
	return fmt.Sprintf("({ %s : %s })", strings.Join(parts, ", "), typName)
}

// bigIntPeephole recognizes select math/big function/method calls and emits
// equivalent Lean Int expressions, bypassing the blackbox path.
//
// Handles:
//   - big.NewInt(x)           → (x : Int)  (or `(x).toInt` for a runtime int64)
//   - new(big.Int).Lsh(x, n)  → x * 2 ^ n  at Int kind
//   - new(big.Int).Rsh(x, n)  → x / 2 ^ n  at Int kind
//
// Other math/big methods (Cmp, Add, Mul, BitLen, SetBit, …) are not matched.
func (b *funcBody) bigIntPeephole(e *ast.CallExpr, fn *types.Func) (string, bool) {
	if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "math/big" {
		return "", false
	}
	switch fn.Name() {
	case "NewInt":
		if len(e.Args) != 1 {
			b.errf(e.Pos(), "big.NewInt expects one argument")
		}
		return b.atom(e.Args[0], kind{base: baseBigInt}), true
	case "Lsh", "Rsh":
		if len(e.Args) != 2 {
			b.errf(e.Pos(), "big.Int.%s expects two arguments", fn.Name())
		}
		sel, ok := unparen(e.Fun).(*ast.SelectorExpr)
		if !ok {
			b.errf(e.Pos(), "unexpected big.Int.%s call form", fn.Name())
		}
		// Receiver must be `new(big.Int)` — a fresh scratch buffer no
		// other name reaches. Any other receiver would silently drop
		// the in-place mutation Lsh / Rsh perform through the pointer.
		recv, _ := unparen(sel.X).(*ast.CallExpr)
		var newBi *types.Builtin
		if recv != nil {
			if id, ok := unparen(recv.Fun).(*ast.Ident); ok {
				newBi, _ = b.info.Uses[id].(*types.Builtin)
			}
		}
		if newBi == nil || newBi.Name() != "new" {
			b.errf(sel.X.Pos(),
				"big.Int.%s receiver must be `new(big.Int)` — %s mutates the receiver in Go, but the translator drops the mutation, so other receiver shapes would produce silently-wrong constraints",
				fn.Name(), fn.Name())
		}
		x := b.atom(e.Args[0], kind{base: baseBigInt})
		n := b.natAtom(e.Args[1])
		op := "*"
		if fn.Name() == "Rsh" {
			op = "/"
		}
		return fmt.Sprintf("%s %s 2 ^ %s", x, op, n), true
	}
	return "", false
}
