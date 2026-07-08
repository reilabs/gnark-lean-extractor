package translator

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
)

// pkgInitCtx returns an exprCtx suitable for folding a package-var
// initializer: there are no bound locals, no receiver, no api parameter, and
// no do-block to lift a monadic subexpression into (so liftMonadic errfs).
func (t *translator) pkgInitCtx() *exprCtx {
	return &exprCtx{
		t:          t,
		resolveObj: func(types.Object, token.Pos) (string, bool) { return "", false },
		isAPI:      func(types.Object) bool { return false },
		liftMonadic: func(_ string, pos token.Pos) string {
			t.errf(pos, "package var initializer cannot contain a monadic (Circuit-valued) expression")
			return ""
		},
	}
}

// resolvePkgVar returns the Lean name for a package-level Var, emitting a
// top-level `def <name> : <T> := <expr>` on first use by folding the
// initializer through the main expression walker. Errors via t.errf if the
// var has no initializer or its shape is not foldable.
func (t *translator) resolvePkgVar(v *types.Var) string {
	if name, ok := t.pkgVars[v]; ok {
		return name
	}

	var spec *ast.ValueSpec
	var idx int
	for _, file := range t.pkg.Syntax {
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if t.pkg.TypesInfo.Defs[name] == v {
						spec, idx = vs, i
					}
				}
			}
		}
	}
	if spec == nil || len(spec.Values) <= idx {
		t.errf(v.Pos(), "package var %s has no initializer to fold", v.Name())
	}

	init := spec.Values[idx]
	k := t.classify(v.Type(), v.Pos())
	str, _ := t.pkgInitCtx().exprTop(init, k)

	name := t.uniqueName(v.Name())
	t.pkgVars[v] = name
	t.defs = append(t.defs,
		fmt.Sprintf("def %s : %s := %s", name, t.leanType(k), str))
	return name
}
