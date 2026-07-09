package translator

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
	"math/big"
)

// bigIntPeephole recognizes select math/big function/method calls and emits
// equivalent Lean Int expressions, bypassing the blackbox path.
//
// Handles:
//   - big.NewInt(x)               → (x : Int)  (or `(x).toInt` for a runtime int64)
//   - new(big.Int).Lsh(x, n)      → x * 2 ^ n  at Int kind
//   - new(big.Int).Rsh(x, n)      → x / 2 ^ n  at Int kind
//   - new(big.Int).Set(x)         → x  at Int kind (identity — receiver dropped)
//   - new(big.Int).SetString(s,b) → parsed literal, folded at translate time
//
// Every method peephole requires a `new(big.Int)` receiver so dropping
// the in-place mutation is sound. Other math/big methods (Cmp, Add, Mul,
// BitLen, SetBytes, SetBit, …) are not matched.
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
		b.requireNewBigIntReceiver(e, fn.Name())
		x := b.atom(e.Args[0], kind{base: baseBigInt})
		n := b.natAtom(e.Args[1])
		op := "*"
		if fn.Name() == "Rsh" {
			op = "/"
		}
		return fmt.Sprintf("%s %s 2 ^ %s", x, op, n), true
	case "Set":
		if len(e.Args) != 1 {
			b.errf(e.Pos(), "big.Int.Set expects one argument")
		}
		b.requireNewBigIntReceiver(e, "Set")
		// `new(big.Int).Set(x)` copies x's value into the fresh scratch
		// receiver and returns the receiver. Under receiver-drop that's
		// just x's value — an identity at Int kind.
		return b.atom(e.Args[0], kind{base: baseBigInt}), true
	case "SetString":
		if len(e.Args) != 2 {
			b.errf(e.Pos(), "big.Int.SetString expects two arguments")
		}
		b.requireNewBigIntReceiver(e, "SetString")
		return b.foldSetString(e), true
	}
	return "", false
}

// requireNewBigIntReceiver errfs unless the callee's receiver expression
// is exactly `new(big.Int)` — a fresh unaliased scratch buffer. Shared by
// every math/big method peephole that drops the receiver.
func (b *funcBody) requireNewBigIntReceiver(e *ast.CallExpr, methodName string) {
	sel, ok := unparen(e.Fun).(*ast.SelectorExpr)
	if !ok {
		b.errf(e.Pos(), "unexpected big.Int.%s call form", methodName)
	}
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
			methodName, methodName)
	}
}

// foldSetString parses the constant string + base at translate time and
// emits the resulting integer as a Lean `(N : Int)` literal. Only decimal
// (base 10) and hex (base 16) are accepted — the same subset math/big
// uses for round-trippable numeric encodings.
func (b *funcBody) foldSetString(e *ast.CallExpr) string {
	strVal, ok := stringLiteralValue(b.info, e.Args[0])
	if !ok {
		b.errf(e.Args[0].Pos(), "big.Int.SetString requires a string literal first argument")
	}
	baseTV, ok := b.info.Types[e.Args[1]]
	if !ok || baseTV.Value == nil || baseTV.Value.Kind() != constant.Int {
		b.errf(e.Args[1].Pos(), "big.Int.SetString requires a constant integer base")
	}
	base64, ok := constant.Int64Val(baseTV.Value)
	if !ok || (base64 != 10 && base64 != 16) {
		b.errf(e.Args[1].Pos(), "big.Int.SetString base must be 10 or 16")
	}
	parsed, ok := new(big.Int).SetString(strVal, int(base64))
	if !ok {
		b.errf(e.Args[0].Pos(), "big.Int.SetString could not parse %q at base %d", strVal, base64)
	}
	return fmt.Sprintf("(%s : Int)", parsed.String())
}
