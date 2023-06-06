package extractor

import (
	"fmt"
	"strings"
)

func ExportGadget(gadget ExGadget) string {
	kArgsType := "F"
	if len(gadget.Outputs) > 1 {
		kArgsType = fmt.Sprintf("Vect F %d", len(gadget.Outputs))
	}
	inAssignment := make([]string, gadget.Arity)
	for i := 0; i < gadget.Arity; i++ {
		inAssignment[i] = fmt.Sprintf("in_%d", i)
	}
	return fmt.Sprintf("def %s %s (k: %s -> Prop): Prop :=\n%s", gadget.Name, genArgs(inAssignment), kArgsType, genGadgetBody(inAssignment, gadget))
}

func ExportCircuit(circuit ExCircuit) string {
	gadgets := make([]string, len(circuit.Gadgets))
	for i, gadget := range circuit.Gadgets {
		gadgets[i] = ExportGadget(gadget)
	}
	circ := fmt.Sprintf("def circuit %s: Prop :=\n%s", genArgs(circuit.Inputs), genCircuitBody(circuit))
	return fmt.Sprintf("%s\n\n%s", strings.Join(gadgets, "\n\n"), circ)
}

func genArgs(inAssignment []string) string {
	args := make([]string, len(inAssignment))
	for i, in := range inAssignment {
		args[i] = fmt.Sprintf("(%s: F)", in)
	}
	return strings.Join(args, " ")
}

func extractBaseArg(arg Operand) Operand {
	switch arg.(type) {
	case Proj:
		return extractBaseArg(arg.(Proj).Operand)
	default:
		return arg
	}
}

func assignGateVars(code []App, additional ...Operand) []string {
	gateVars := make([]string, len(code))
	for _, app := range code {
		for _, arg := range app.Args {
			base := extractBaseArg(arg)
			switch base.(type) {
			case Gate:
				ix := base.(Gate).Index
				if gateVars[ix] == "" {
					gateVars[ix] = fmt.Sprintf("gate_%d", ix)
				}
			}
		}
	}
	for _, out := range additional {
		outBase := extractBaseArg(out)
		switch outBase.(type) {
		case Gate:
			ix := outBase.(Gate).Index
			if gateVars[ix] == "" {
				gateVars[ix] = fmt.Sprintf("gate_%d", ix)
			}
		}
	}
	return gateVars
}

func genGadgetCall(gateVar string, inAssignment []string, gateVars []string, gadget *ExGadget, args []Operand) string {
	name := gadget.Name
	operands := strings.Join(operandExprs(args, inAssignment, gateVars), " ")
	binder := "_"
	if gateVar != "" {
		binder = gateVar
	}
	return fmt.Sprintf("    %s %s fun %s =>\n", name, operands, binder)
}

func genOpCall(gateVar string, inAssignment []string, gateVars []string, op Op, args []Operand) string {
	name := "unknown"
	switch op {
	case OpAdd:
		name = "add"
	case OpMul:
		name = "mul"
	case OpSub:
		name = "sub"
	case OpDiv:
		name = "div"
	case OpAssertEq:
		name = "eq"
	case OpAssertNotEq:
		name = "ne"
	}
	functional := false
	switch op {
	case OpAdd, OpMul, OpSub, OpDiv:
		functional = true
	}
	name = fmt.Sprintf("Gates.%s", name)
	operands := strings.Join(operandExprs(args, inAssignment, gateVars), " ")
	if functional {
		varName := "_ignored_"
		if gateVar != "" {
			varName = gateVar
		}
		binder := fmt.Sprintf("∃%s, %s = ", varName, varName)
		return fmt.Sprintf("    %s%s %s ∧\n", binder, name, operands)
	} else {
		return fmt.Sprintf("    %s %s ∧\n", name, operands)
	}
}

func genLine(app App, gateVar string, inAssignment []string, gateVars []string) string {
	switch app.Op.(type) {
	case *ExGadget:
		return genGadgetCall(gateVar, inAssignment, gateVars, app.Op.(*ExGadget), app.Args)
	case Op:
		return genOpCall(gateVar, inAssignment, gateVars, app.Op.(Op), app.Args)
	}
	return ""
}

func genGadgetBody(inAssignment []string, gadget ExGadget) string {
	gateVars := assignGateVars(gadget.Code, gadget.Outputs...)
	lines := make([]string, len(gadget.Code))
	for i, app := range gadget.Code {
		lines[i] = genLine(app, gateVars[i], inAssignment, gateVars)
	}
	outs := operandExprs(gadget.Outputs, inAssignment, gateVars)
	result := outs[0]
	if len(gadget.Outputs) > 1 {
		result = fmt.Sprintf("vec![%s]", strings.Join(outs, ", "))
	}
	lastLine := fmt.Sprintf("    k %s", result)
	return strings.Join(append(lines, lastLine), "")
}

func genCircuitBody(circuit ExCircuit) string {
	gateVars := assignGateVars(circuit.Code)
	lines := make([]string, len(circuit.Code))
	for i, app := range circuit.Code {
		lines[i] = genLine(app, gateVars[i], circuit.Inputs, gateVars)
	}
	lastLine := "    True"
	return strings.Join(append(lines, lastLine), "")
}

func operandExpr(operand Operand, inAssignment []string, gateVars []string) string {
	switch operand.(type) {
	case Input:
		return inAssignment[operand.(Input).Index]
	case Gate:
		return gateVars[operand.(Gate).Index]
	case Proj:
		return fmt.Sprintf("%s[%d]", operandExpr(operand.(Proj).Operand, inAssignment, gateVars), operand.(Proj).Index)
	case Const:
		return operand.(Const).Value.Text(10)
	default:
		panic("not yet supported")
	}
}

func operandExprs(operands []Operand, inAssignment []string, gateVars []string) []string {
	exprs := make([]string, len(operands))
	for i, operand := range operands {
		exprs[i] = operandExpr(operand, inAssignment, gateVars)
	}
	return exprs
}
