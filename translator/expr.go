package translator

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
)

// exprCtx owns expression translation. It pairs the shared translator (for
// blackbox axioms, struct registration, callee lookup, and other cross-scope
// state) with a handful of scope-varying callbacks: how to resolve an
// identifier to a Lean name, whether an object is the enclosing function's
// frontend.API parameter, and how to bind a Circuit-valued term into the
// current do-block. `funcBody` supplies the in-function view;
// `translator.pkgInitCtx` supplies an "outside any function" view for
// folding package-var initializers (its liftMonadic errfs — package-var
// initializers can't contain monadic subexpressions).
type exprCtx struct {
	t           *translator
	resolveObj  func(obj types.Object, pos token.Pos) (string, bool)
	isAPI       func(obj types.Object) bool
	liftMonadic func(str string, pos token.Pos) string
}

func (t *translator) info() *types.Info { return t.pkg.TypesInfo }

func (t *translator) kindOf(e ast.Expr) kind {
	return t.classify(t.info().TypeOf(e), e.Pos())
}

// renderConst renders a folded Go constant at the wanted Lean kind.
func (t *translator) renderConst(v constant.Value, want kind, pos token.Pos) string {
	if v.Kind() == constant.Bool {
		if constant.BoolVal(v) {
			return "true"
		}
		return "false"
	}
	if v.Kind() != constant.Int {
		t.errf(pos, "unsupported constant %s", v)
	}
	s := v.ExactString()
	if want.goInt {
		// Bare numerals elaborate against the expected Int64 type;
		// let-bindings get an explicit ascription instead.
		return s
	}
	return fmt.Sprintf("(%s : F)", s)
}

// isIntValued reports whether e is a non-constant Go integer expression
// (constants render directly at the wanted type instead).
func (t *translator) isIntValued(e ast.Expr) bool {
	if tv, ok := t.info().Types[e]; ok && tv.Value != nil {
		return false
	}
	typ := t.info().TypeOf(e)
	if typ == nil {
		return false
	}
	b, ok := typ.Underlying().(*types.Basic)
	if !ok || b.Info()&types.IsInteger == 0 {
		return false
	}
	// byte / uint8 already crosses into F via the []byte classification —
	// no `.toInt` bridge is needed (and would fail since the value is F).
	return b.Kind() != types.Uint8
}

// zeroValueOf renders the Lean expression corresponding to Go's zero value
// at kind k / underlying type typ.
func (t *translator) zeroValueOf(k kind, typ types.Type, pos token.Pos) string {
	if k.goInt {
		return "(0 : Int64)"
	}
	if k.goBool {
		return "false"
	}
	if k.depth == 0 {
		if k.opaque != "" || k.named != nil {
			return "default"
		}
		return "(0 : F)"
	}
	// Array with a fixed length — replicate the zero-of-elem k.length times.
	// Slice has no compile-time length, so we can only produce `[]` (empty).
	if arr, ok := typ.Underlying().(*types.Array); ok {
		elemK := k.elem()
		return fmt.Sprintf("List.replicate %d %s", arr.Len(), t.zeroValueOf(elemK, arr.Elem(), pos))
	}
	return "[]"
}

// zeroForKind is a type-free wrapper used when only the kind is known
// (named returns, since their declared types aren't easy to thread).
func (t *translator) zeroForKind(k kind) string {
	if k.goInt {
		return "(0 : Int64)"
	}
	if k.goBool {
		return "false"
	}
	if k.depth == 0 {
		if k.opaque != "" || k.named != nil {
			return "default"
		}
		return "(0 : F)"
	}
	return "[]"
}

func (t *translator) callee(call *ast.CallExpr) types.Object {
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
		return t.info().Uses[fn]
	case *ast.SelectorExpr:
		return t.info().Uses[fn.Sel]
	}
	return nil
}

// atom translates an expression to a Lean term suitable for use as a
// function argument: monadic subexpressions are lifted via the scope,
// compound pure expressions are parenthesized.
func (c *exprCtx) atom(e ast.Expr, want kind) string {
	str, monadic := c.exprTop(e, want)
	if monadic {
		return c.liftMonadic(str, e.Pos())
	}
	return wrapParen(str)
}

// exprTop translates an expression, returning the Lean term and whether
// it is monadic (`Circuit _`-valued) at the top level. A Go integer
// expression in a Variable position is a gnark constant: it enters the
// field through .toInt mod p.
func (c *exprCtx) exprTop(e ast.Expr, want kind) (string, bool) {
	str, monadic := c.exprBare(e, want)
	if !monadic && !want.goInt && want.depth == 0 && c.t.isIntValued(e) {
		return fmt.Sprintf("((%s).toInt : F)", str), false
	}
	return str, monadic
}

// exprBare translates a Go expression to Lean, per-shape.
func (c *exprCtx) exprBare(e ast.Expr, want kind) (string, bool) {
	if tv, ok := c.t.info().Types[e]; ok && tv.Value != nil {
		return c.t.renderConst(tv.Value, want, e.Pos()), false
	}
	switch e := e.(type) {
	case *ast.ParenExpr:
		return c.exprBare(e.X, want)
	case *ast.Ident:
		obj := c.t.info().Uses[e]
		if name, ok := c.resolveObj(obj, e.Pos()); ok {
			return name, false
		}
		// Package-level Var with a foldable initializer.
		if v, ok := obj.(*types.Var); ok && v.Parent() == c.t.pkg.Types.Scope() {
			return c.t.resolvePkgVar(v), false
		}
		c.t.errf(e.Pos(), "unknown identifier %s", e.Name)
	case *ast.SelectorExpr:
		sel, ok := c.t.info().Selections[e]
		if !ok || sel.Kind() != types.FieldVal {
			c.t.errf(e.Pos(), "unsupported selector expression")
		}
		// Circuit fields and named locals resolve directly.
		if name, ok := c.resolveObj(sel.Obj(), e.Pos()); ok {
			return name, false
		}
		// Nested field access: translate the base and append `.Field`.
		baseStr, monadic := c.exprBare(e.X, kind{})
		if monadic {
			c.t.errf(e.Pos(), "cannot select a field of a monadic expression")
		}
		return wrapParen(baseStr) + "." + sanitize(sel.Obj().Name()), false
	case *ast.IndexExpr:
		base := c.atom(e.X, c.t.kindOf(e.X))
		return fmt.Sprintf("%s[%s]!", base, c.natRaw(e.Index)), false
	case *ast.SliceExpr:
		if e.Slice3 {
			c.t.errf(e.Pos(), "three-index slice expressions are not supported")
		}
		base := c.atom(e.X, c.t.kindOf(e.X))
		// xs[:]       -> xs (identity)
		// xs[a:]      -> xs.drop a
		// xs[:b]      -> xs.take b
		// xs[a:b]     -> (xs.drop a).take (b - a)
		switch {
		case e.Low == nil && e.High == nil:
			return base, false
		case e.Low == nil:
			return fmt.Sprintf("%s.take %s", base, c.natAtom(e.High)), false
		case e.High == nil:
			return fmt.Sprintf("%s.drop %s", base, c.natAtom(e.Low)), false
		default:
			lo := c.natAtom(e.Low)
			hi := c.natAtom(e.High)
			return fmt.Sprintf("(%s.drop %s).take (%s - %s)", base, lo, hi, lo), false
		}
	case *ast.CallExpr:
		return c.call(e)
	case *ast.CompositeLit:
		k := c.t.classify(c.t.info().TypeOf(e), e.Pos())
		if k.named != nil && k.depth == 0 {
			return c.structLit(e, k), false
		}
		if k.goInt || k.depth == 0 {
			c.t.errf(e.Pos(), "unsupported composite literal type")
		}
		elems := make([]string, len(e.Elts))
		for i, el := range e.Elts {
			if _, ok := el.(*ast.KeyValueExpr); ok {
				c.t.errf(el.Pos(), "keyed composite literals are not supported")
			}
			elems[i] = c.atom(el, k.elem())
		}
		return "[" + strings.Join(elems, ", ") + "]", false
	case *ast.UnaryExpr:
		// `&x` is Go noise around passing a value struct/slice to a
		// helper. Erase the pointer op: the translation carries the value
		// through directly.
		if e.Op == token.AND {
			return c.exprBare(e.X, want)
		}
		// `!x` on Go bool → Lean Bool negation. Circuit-level `!` is
		// still routed through the gates path in cond().
		if e.Op == token.NOT {
			inner, monadic := c.exprBare(e.X, kind{goBool: true})
			return "!" + wrapParen(inner), monadic
		}
		c.t.errf(e.Pos(), "unsupported unary operator %s", e.Op)
	case *ast.StarExpr:
		// `*p` — the dual of `&x`. Only accept when the operand is a
		// pointer to a value the translator already models (a value
		// receiver / by-value struct or slice), not e.g. a pointer field.
		if _, ok := c.t.info().TypeOf(e.X).(*types.Pointer); !ok {
			c.t.errf(e.Pos(), "cannot dereference non-pointer expression")
		}
		return c.exprBare(e.X, want)
	case *ast.BinaryExpr:
		if !c.t.kindOf(e.X).goInt {
			c.t.errf(e.Pos(), "arithmetic on Variables must go through the api")
		}
		gi := kind{goInt: true}
		x, y := c.atom(e.X, gi), c.atom(e.Y, gi)
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
			c.t.errf(e.Pos(), "unsupported integer operator %s", e.Op)
		}
	}
	c.t.errf(e.Pos(), "unsupported expression %T", e)
	return "", false
}

// natRaw translates a Go integer expression used where Lean expects a Nat
// (indices, lengths, bit counts): constants render as numerals, everything
// else crosses the boundary through .toInt.toNat (clamping negatives to 0,
// where Go panics instead).
func (c *exprCtx) natRaw(e ast.Expr) string {
	if tv, ok := c.t.info().Types[e]; ok && tv.Value != nil {
		if tv.Value.Kind() != constant.Int {
			c.t.errf(e.Pos(), "unsupported constant %s", tv.Value)
		}
		s := tv.Value.ExactString()
		if strings.HasPrefix(s, "-") {
			c.t.errf(e.Pos(), "constant negative index or size")
		}
		return s
	}
	// len(xs) used as a size is already a Nat; skip the Int64 round-trip.
	if call, ok := unparen(e).(*ast.CallExpr); ok {
		if id, ok := unparen(call.Fun).(*ast.Ident); ok {
			if b, ok := c.t.info().Uses[id].(*types.Builtin); ok && b.Name() == "len" {
				return c.atom(call.Args[0], c.t.kindOf(call.Args[0])) + ".length"
			}
		}
	}
	return c.atom(e, kind{goInt: true}) + ".toInt.toNat"
}

func (c *exprCtx) natAtom(e ast.Expr) string {
	return wrapParen(c.natRaw(e))
}

func (c *exprCtx) call(e *ast.CallExpr) (string, bool) {
	// Type conversions (uint32(n), frontend.Variable(0), ...) pass through.
	if tv, ok := c.t.info().Types[e.Fun]; ok && tv.IsType() {
		// []byte("...") — fold the string literal at translate time into
		// a `List F` of byte-wide numerals.
		if isByteSliceType(tv.Type) {
			if s, ok := stringLiteralValue(c.t.info(), e.Args[0]); ok {
				parts := make([]string, len(s))
				for i := 0; i < len(s); i++ {
					parts[i] = fmt.Sprintf("(%d : F)", s[i])
				}
				return "[" + strings.Join(parts, ", ") + "]", false
			}
			c.t.errf(e.Pos(), "only string-literal []byte conversions are supported")
		}
		return c.exprTop(e.Args[0], c.t.classify(tv.Type, e.Pos()))
	}

	// Builtins.
	if id, ok := unparen(e.Fun).(*ast.Ident); ok {
		if b, ok := c.t.info().Uses[id].(*types.Builtin); ok {
			switch b.Name() {
			case "len":
				return "Int64.ofNat " + c.atom(e.Args[0], c.t.kindOf(e.Args[0])) + ".length", false
			case "append":
				bk := c.t.kindOf(e.Args[0])
				base := c.atom(e.Args[0], bk)
				if e.Ellipsis.IsValid() {
					return fmt.Sprintf("%s ++ %s", base, c.atom(e.Args[1], bk)), false
				}
				if len(e.Args) == 2 {
					return fmt.Sprintf("%s.concat %s", base, c.atom(e.Args[1], bk.elem())), false
				}
				// append(xs, a, b, ...): concat with a fresh list literal.
				elems := make([]string, len(e.Args)-1)
				for i, a := range e.Args[1:] {
					elems[i] = c.atom(a, bk.elem())
				}
				return fmt.Sprintf("%s ++ [%s]", base, strings.Join(elems, ", ")), false
			case "make":
				if len(e.Args) < 2 || len(e.Args) > 3 {
					c.t.errf(e.Pos(), "make requires a length (and optional capacity)")
				}
				mk := c.t.classify(c.t.info().TypeOf(e), e.Pos())
				n := c.natAtom(e.Args[1])
				return fmt.Sprintf("List.replicate %s %s", n, c.t.zeroForKind(mk.elem())), false
			default:
				c.t.errf(e.Pos(), "unsupported builtin %s", b.Name())
			}
		}
	}

	// api method calls become gates.
	if sel, ok := unparen(e.Fun).(*ast.SelectorExpr); ok {
		if id, ok := unparen(sel.X).(*ast.Ident); ok && c.isAPI(c.t.info().Uses[id]) {
			return c.gate(sel.Sel.Name, e)
		}
	}

	// Static function calls: blackboxed or translated.
	fn, ok := c.t.callee(e).(*types.Func)
	if !ok {
		c.t.errf(e.Pos(), "unsupported call")
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
			c.t.errf(e.Pos(), "abstractor.%s expects (api, gadget)", fn.Name())
		}
		gadgetArg := e.Args[1]
		gadgetType := c.t.info().TypeOf(gadgetArg)
		method, _, _ := types.LookupFieldOrMethod(gadgetType, true, fn.Pkg(), "DefineGadget")
		defineFn, _ := method.(*types.Func)
		if defineFn == nil {
			c.t.errf(e.Pos(), "%s has no DefineGadget method", gadgetType)
		}
		gadgetStr := c.atom(gadgetArg, c.t.classify(gadgetType, e.Pos()))
		if defineFn.Pkg() != c.t.pkg.Types {
			// Foreign gadget: axiomatize DefineGadget with the wrapper's
			// return kind. The gadget struct itself is already registered
			// by the classify call above.
			c.t.ensureGadgetAxiom(defineFn, gadgetType.(*types.Named), fn.Name(), e.Pos())
		} else {
			c.t.translateFunc(defineFn, e.Pos())
		}
		return gadgetStr + ".DefineGadget", true
	}
	if leanName, ok := c.t.cfg.Blackboxes[full]; ok {
		actual := c.t.ensureAxiom(leanName, fn, e.Pos())
		return actual + c.callArgs(e, fn), true
	}
	if fn.Pkg() == c.t.pkg.Types {
		name := c.t.translateFunc(fn, e.Pos())
		// For method calls, emit `<receiver>.<Method> <args>` dot syntax
		// (the receiver is the SelectorExpr base, not in call.Args).
		if fn.Type().(*types.Signature).Recv() != nil {
			sel, ok := unparen(e.Fun).(*ast.SelectorExpr)
			if !ok {
				c.t.errf(e.Pos(), "unexpected method call form")
			}
			recvStr := c.atom(sel.X, c.t.kindOf(sel.X))
			return recvStr + "." + fn.Name() + c.callArgs(e, fn), true
		}
		return name + c.callArgs(e, fn), true
	}
	c.t.errf(e.Pos(), "call to %s is not supported — register it as a blackbox", full)
	return "", false
}

// callArgs renders the arguments of a helper/blackbox call, dropping the
// frontend.API argument. Variadic callees are accepted in two shapes: the
// spread form `f(a, xs...)` — the ellipsis arg carries the whole slice —
// and the bundled form `f(a, b, c)` where the variadic tail is folded into
// a Lean list literal at the call site.
func (c *exprCtx) callArgs(e *ast.CallExpr, fn *types.Func) string {
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
		out.WriteString(c.atom(e.Args[i], c.t.classify(pt, e.Args[i].Pos())))
	}
	if !variadic {
		return out.String()
	}
	// Variadic tail.
	sliceType, _ := sig.Params().At(nParams - 1).Type().(*types.Slice)
	var elemKind kind
	if sliceType != nil {
		elemKind = c.t.classify(sliceType.Elem(), e.Pos())
	}
	tail := e.Args[fixed:]
	if e.Ellipsis.IsValid() && len(tail) == 1 {
		// Spread: the caller already has a slice; pass through as-is.
		listKind := kind{depth: elemKind.depth + 1, named: elemKind.named, opaque: elemKind.opaque}
		out.WriteString(" ")
		out.WriteString(c.atom(tail[0], listKind))
		return out.String()
	}
	// Bundle variadic args into a fresh list literal.
	parts := make([]string, len(tail))
	for i, a := range tail {
		parts[i] = c.atom(a, elemKind)
	}
	out.WriteString(" [")
	out.WriteString(strings.Join(parts, ", "))
	out.WriteString("]")
	return out.String()
}

// gate translates a frontend.API method call.
func (c *exprCtx) gate(name string, call *ast.CallExpr) (string, bool) {
	if call.Ellipsis.IsValid() && name != "FromBinary" {
		c.t.errf(call.Pos(), "spread arguments to api.%s are not supported", name)
	}
	arg := func(i int) string { return c.atom(call.Args[i], kind{}) }
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
			return "Gates.fromBinary " + c.atom(call.Args[0], kind{depth: 1}), false
		}
		var bits []string
		for i := range call.Args {
			bits = append(bits, c.atom(call.Args[i], kind{}))
		}
		return fmt.Sprintf("Gates.fromBinary [%s]", strings.Join(bits, ", ")), false
	case "Div":
		return fmt.Sprintf("Gates.div %s %s", arg(0), arg(1)), true
	case "DivUnchecked":
		return fmt.Sprintf("Gates.divUnchecked %s %s", arg(0), arg(1)), true
	case "Inverse":
		return "Gates.inv " + arg(0), true
	case "ToBinary":
		n := fmt.Sprintf("%d", c.t.cfg.Field.ScalarField().BitLen())
		if len(call.Args) == 2 {
			n = c.natAtom(call.Args[1])
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
	c.t.errf(call.Pos(), "unsupported api method %s", name)
	return "", false
}

// synthesizeCircuitLiteral produces a Lean struct value for the Define
// receiver, so `circuit.method(...)` translates as a dot-syntax call on a
// synthesized record. Registers the Circuit type as a Lean structure on
// demand — nothing is emitted for circuits whose bodies never take the
// receiver's value.
func (t *translator) synthesizeCircuitLiteral(pos token.Pos) string {
	obj := t.pkg.Types.Scope().Lookup(t.cfg.Circuit)
	if obj == nil {
		t.errf(pos, "circuit type %s not found", t.cfg.Circuit)
	}
	named, ok := obj.Type().(*types.Named)
	if !ok {
		t.errf(pos, "circuit type %s is not a named struct", t.cfg.Circuit)
	}
	st, ok := named.Underlying().(*types.Struct)
	if !ok {
		t.errf(pos, "circuit type %s is not a struct", t.cfg.Circuit)
	}
	t.classify(named, pos)
	structName := t.structReg.name(named)
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
func (c *exprCtx) structLit(e *ast.CompositeLit, k kind) string {
	st := k.named.Underlying().(*types.Struct)
	typName := c.t.structReg.name(k.named)
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
				c.t.errf(el.Pos(), "mixed keyed/positional struct literal")
			}
			keyId, ok := kv.Key.(*ast.Ident)
			if !ok {
				c.t.errf(kv.Key.Pos(), "struct literal key must be a field name")
			}
			supplied[keyId.Name] = kv.Value
		}
		for i := 0; i < st.NumFields(); i++ {
			fld := st.Field(i)
			fk := c.t.classify(fld.Type(), e.Pos())
			var val string
			if v, ok := supplied[fld.Name()]; ok {
				val = c.atom(v, fk)
			} else {
				val = c.t.zeroForKind(fk)
			}
			parts = append(parts, fmt.Sprintf("%s := %s", sanitize(fld.Name()), val))
		}
	} else {
		if len(e.Elts) != st.NumFields() {
			c.t.errf(e.Pos(), "positional struct literal must supply all fields of %s", typName)
		}
		for i, el := range e.Elts {
			fld := st.Field(i)
			fk := c.t.classify(fld.Type(), el.Pos())
			parts = append(parts, fmt.Sprintf("%s := %s", sanitize(fld.Name()), c.atom(el, fk)))
		}
	}
	return fmt.Sprintf("({ %s : %s })", strings.Join(parts, ", "), typName)
}
