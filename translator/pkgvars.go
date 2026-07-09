package translator

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
)

// newPkgInitBody returns a funcBody used solely as an expression walker for
// folding a package-var initializer: no bound locals, no receiver, no api,
// and isPkgInit so liftMonadic errfs — a package-var initializer can't
// contain a Circuit-valued subexpression.
func (b *funcBody) newPkgInitBody() *funcBody {
	return &funcBody{
		cfg:       b.cfg,
		pkg:       b.pkg,
		info:      b.info,
		emit:      b.emit,
		isPkgInit: true,
		names:     map[types.Object]string{},
	}
}

// resolvePkgVar returns the Lean name for a package-level Var, emitting a
// top-level `def <name> : <T> := <expr>` on first use by folding the
// initializer through the main expression walker. Errors via b.errf if the
// var has no initializer or its shape is not foldable.
func (b *funcBody) resolvePkgVar(v *types.Var) string {
	return b.emit.pkgVarReg.getOrRegister(v, func(name string) string {
		var spec *ast.ValueSpec
		var idx int
		for _, file := range b.pkg.Syntax {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, s := range gd.Specs {
					vs := s.(*ast.ValueSpec)
					for i, nm := range vs.Names {
						if b.pkg.TypesInfo.Defs[nm] == v {
							spec, idx = vs, i
						}
					}
				}
			}
		}
		if spec == nil || len(spec.Values) <= idx {
			b.errf(v.Pos(), "package var %s has no initializer to fold", v.Name())
		}

		init := spec.Values[idx]
		k := b.classify(v.Type(), v.Pos())
		str, _ := b.newPkgInitBody().exprTop(init, k)
		return fmt.Sprintf("def %s : %s := %s", name, b.leanType(k), str)
	})
}
