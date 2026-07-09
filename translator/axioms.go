package translator

import (
	"fmt"
	"go/token"
	"go/types"
	"strings"
)

// ensureGadgetAxiom emits an opaque predicate + Circuit-monad wrapper for a
// gadget whose DefineGadget method lives in a foreign package. The wrapper's
// return kind (F, List F, …) comes from the abstractor variant at the call
// site: Call → F, CallVoid → Unit, Call1/2/3 → List{1,2,3} F.
func (b *funcBody) ensureGadgetAxiom(defineFn *types.Func, gadgetType *types.Named, wrapperName string, pos token.Pos) {
	slot := b.emit.funcReg.slot(defineFn)
	if slot.done {
		return
	}
	structName := b.emit.structReg.name(gadgetType)
	if structName == "" {
		b.errf(pos, "gadget %s has no registered structure", gadgetType.Obj().Name())
	}
	predName := structName + "_DefineGadget_pred"
	defName := structName + ".DefineGadget"
	b.emit.alloc.reserveExact(predName)
	b.emit.alloc.reserveExact(defName)
	slot.leanName = defName
	slot.done = true

	var axiom, def string
	if wrapperName == "CallVoid" {
		axiom = fmt.Sprintf("axiom %s : %s → Prop", predName, structName)
		def = fmt.Sprintf("def %s (g : %s) : Circuit Unit := fun k =>\n  %s g ∧ k ()",
			defName, structName, predName)
	} else {
		var resKind kind
		switch wrapperName {
		case "Call":
			resKind = kind{}
		case "Call1":
			resKind = kind{depth: 1}
		case "Call2":
			resKind = kind{depth: 2}
		case "Call3":
			resKind = kind{depth: 3}
		default:
			b.errf(pos, "unsupported abstractor variant %s", wrapperName)
		}
		axiom = fmt.Sprintf("axiom %s : %s → %s → Prop", predName, structName, b.leanType(resKind))
		def = fmt.Sprintf("def %s (g : %s) : Circuit %s := fun k =>\n  ∃ out, %s g out ∧ k out",
			defName, structName, b.leanTypeParen(resKind), predName)
	}
	b.emit.axioms = append(b.emit.axioms, axiom+"\n"+def)
}

// ensureAxiom emits an axiom + wrapper for a blackboxed function. Returns
// the emitted Lean name — which may differ from the requested one if a
// collision (e.g. with the outer namespace) forced a suffix.
func (b *funcBody) ensureAxiom(leanName string, fn *types.Func, pos token.Pos) string {
	return b.emit.axiomReg.getOrRegister(leanName, func(actual string) string {
		// Also reserve the companion predicate name so it can't be shadowed.
		b.emit.alloc.reserveExact(actual + "_pred")

		sig := fn.Type().(*types.Signature)
		var binders, predArgTypes, argNames []string
		for i := 0; i < sig.Params().Len(); i++ {
			p := sig.Params().At(i)
			if isAPI(p.Type()) {
				continue
			}
			k := b.classify(p.Type(), pos)
			name := sanitize(p.Name())
			if name == "" || name == "_" {
				name = fmt.Sprintf("x%d", i)
			}
			binders = append(binders, fmt.Sprintf("(%s : %s)", name, b.leanType(k)))
			predArgTypes = append(predArgTypes, b.leanType(k))
			argNames = append(argNames, name)
		}

		results, _ := stripTrailingError(sig.Results())
		resKinds := make([]kind, results.Len())
		resTypes := make([]string, results.Len())
		for i := range resKinds {
			resKinds[i] = b.classify(results.At(i).Type(), pos)
			resTypes[i] = b.leanType(resKinds[i])
		}

		// Predicate signatures collapse the arrow chain: if there are no
		// inputs we emit `Prop` (or `<Out> → Prop`) directly, without a
		// leading arrow.
		inSig := ""
		if len(predArgTypes) > 0 {
			inSig = strings.Join(predArgTypes, " → ") + " → "
		}
		binderSig := strings.Join(binders, " ")
		if binderSig != "" {
			binderSig = " " + binderSig
		}
		inArgs := strings.Join(argNames, " ")
		if inArgs != "" {
			inArgs = " " + inArgs
		}

		var axiom, def string
		switch len(resKinds) {
		case 0:
			axiom = fmt.Sprintf("axiom %s_pred : %sProp", actual, inSig)
			def = fmt.Sprintf("def %s%s : Circuit Unit := fun k =>\n  %s_pred%s ∧ k ()",
				actual, binderSig, actual, inArgs)
		case 1:
			axiom = fmt.Sprintf("axiom %s_pred : %s%s → Prop", actual, inSig, resTypes[0])
			def = fmt.Sprintf("def %s%s : Circuit %s := fun k =>\n  ∃ out, %s_pred%s out ∧ k out",
				actual, binderSig, b.leanTypeParen(resKinds[0]), actual, inArgs)
		default:
			outNames := make([]string, len(resKinds))
			for i := range outNames {
				outNames[i] = fmt.Sprintf("out%d", i+1)
			}
			axiom = fmt.Sprintf("axiom %s_pred : %s%s → Prop",
				actual, inSig, strings.Join(resTypes, " → "))
			callArgs := inArgs + " " + strings.Join(outNames, " ")
			def = fmt.Sprintf("def %s%s : Circuit (%s) := fun k =>\n  ∃ %s, %s_pred%s ∧ k (%s)",
				actual, binderSig, strings.Join(resTypes, " × "),
				strings.Join(outNames, " "), actual, callArgs,
				strings.Join(outNames, ", "))
		}
		return axiom + "\n" + def
	})
}
