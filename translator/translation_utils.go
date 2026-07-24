package translator

import (
	"go/ast"
	"go/constant"
	"go/types"
	"regexp"
)

// Shared expression-level helpers used by both the statement handlers and
// the expression walker.

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

func unparen(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// abstractorPkgPath is the import path of the abstractor package hosting
// Call/CallVoid/Call1/2/3.
const abstractorPkgPath = "github.com/reilabs/gnark-lean-extractor/v3/abstractor"

// isAbstractorCallVariant reports whether fn is one of the abstractor's
// gadget-call wrappers. All variants defer to the gadget's DefineGadget
// method; the translator rewrites the call as a direct method invocation.
func isAbstractorCallVariant(fn *types.Func) bool {
	if fn.Pkg() == nil || fn.Pkg().Path() != abstractorPkgPath {
		return false
	}
	switch fn.Name() {
	case "Call", "CallVoid", "Call1", "Call2", "Call3":
		return true
	}
	return false
}

// isByteSliceType reports whether t is `[]byte` (or `[]uint8`).
func isByteSliceType(t types.Type) bool {
	s, ok := t.Underlying().(*types.Slice)
	if !ok {
		return false
	}
	b, ok := s.Elem().Underlying().(*types.Basic)
	return ok && b.Kind() == types.Uint8
}

// stringLiteralValue extracts the (unquoted) value of a string-constant
// expression at translate time.
func stringLiteralValue(info *types.Info, e ast.Expr) (string, bool) {
	tv, ok := info.Types[e]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
}
