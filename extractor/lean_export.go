package extractor

import (
	"fmt"
	"gnark-extractor/abstractor"
	"reflect"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

func ExportGadget(gadget ExGadget) string {
	kArgsType := "F"
	if len(gadget.Outputs) > 1 {
		kArgsType = fmt.Sprintf("Vect F %d", len(gadget.Outputs))
	}
	inAssignment := make([]ExArg, gadget.Arity)
	for i := 0; i < gadget.Arity; i++ {
		inAssignment[i] = ExArg{fmt.Sprintf("in_%d", i), 1, reflect.Interface}
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

func CircuitToLean(circuit abstractor.Circuit, field ecc.ID) error {
	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		Field:   field,
	}
	err := circuit.AbsDefine(&api)
	if err != nil {
		return err
	}
	schema, err := frontend.NewSchema(circuit)
	if err != nil {
		return err
	}
	var circuitInputs []ExArg
	for _, f := range schema.Fields {
		kind := KindOfField(circuit, f.Name)
		arg := ExArg{f.Name, f.ArraySize, kind}
		circuitInputs = append(circuitInputs, arg)
	}
	extractorCircuit := ExCircuit{
		Inputs:  circuitInputs,
		Gadgets: api.Gadgets,
		Code:    api.Code,
	}
	fmt.Println(ExportCircuit(extractorCircuit))
	return nil
}

func KindOfField(a interface{}, s string) reflect.Kind {
	v := reflect.ValueOf(a).Elem()
	f := v.FieldByName(s)
	return f.Kind()
}

func genArgs(inAssignment []ExArg) string {
	args := make([]string, len(inAssignment))
	for i, in := range inAssignment {
		switch in.Type {
		case reflect.Array:
			args[i] = fmt.Sprintf("(%s: Vector Bit %d)", in.Name, in.Size)
		default:
			args[i] = fmt.Sprintf("(%s: F)", in.Name)
		}
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

func genGadgetCall(gateVar string, inAssignment []ExArg, gateVars []string, gadget *ExGadget, args []Operand) string {
	name := gadget.Name
	operands := strings.Join(operandExprs(args, inAssignment, gateVars), " ")
	binder := "_"
	if gateVar != "" {
		binder = gateVar
	}
	return fmt.Sprintf("    %s %s fun %s =>\n", name, operands, binder)
}

func genGateOp(op Op) string {
	name := "unknown"
	switch op {
	case OpAdd:
		name = "add"
	case OpMulAcc:
		name = "mul_acc"
	case OpNegative:
		name = "neg"
	case OpSub:
		name = "sub"
	case OpMul:
		name = "mul"
	case OpDivUnchecked:
		name = "div_unchecked"
	case OpDiv:
		name = "div"
	case OpInverse:
		name = "inv"
	case OpXor:
		name = "xor"
	case OpOr:
		name = "or"
	case OpAnd:
		name = "and"
	case OpSelect:
		name = "select"
	case OpLookup:
		name = "lookup"
	case OpIsZero:
		name = "is_zero"
	case OpCmp:
		name = "cmp"
	case OpAssertEq:
		name = "eq"
	case OpAssertNotEq:
		name = "ne"
	case OpAssertIsBool:
		name = "is_bool"
	case OpAssertLessEqual:
		name = "le"
	case OpFromBinary:
		name = "from_binary Order"
	case OpToBinary:
		name = "to_binary"
	}

	return fmt.Sprintf("Gates.%s", name)
}

func getGateName(gateVar string, explicit bool) string {
	varName := "_ignored_"
	if gateVar != "" {
		varName = gateVar
	}
	if explicit {
		return fmt.Sprintf("(%s : F)", varName)
	}
	return varName
}

func genGateBinder(gateVar string) string {
	gateName := getGateName(gateVar, false)
	return fmt.Sprintf("∃%s, %s = ", gateName, gateName)
}

func genFunctionalGate(gateVar string, op Op, operands []string) string {
	return fmt.Sprintf("    %s%s %s ∧\n", genGateBinder(gateVar), genGateOp(op), strings.Join(operands, " "))
}

func genCallbackGate(gateVar string, op Op, operands []string) string {
	gateName := getGateName(gateVar, false)
	return fmt.Sprintf("    ∃%s, %s %s %s ∧\n", gateName, genGateOp(op), strings.Join(operands, " "), gateName)
}

func genGenericGate(op Op, operands []string) string {
	return fmt.Sprintf("    %s %s ∧\n", genGateOp(op), strings.Join(operands, " "))
}

func genOpCall(gateVar string, inAssignment []ExArg, gateVars []string, op Op, args []Operand) string {
	// functional is set to true when the op returns a value
	functional := false
	callback := false
	switch op {
	case OpDivUnchecked, OpDiv, OpInverse, OpXor, OpOr, OpAnd, OpSelect, OpLookup, OpCmp, OpIsZero, OpToBinary:
		callback = true
	case OpAdd, OpMulAcc, OpNegative, OpSub, OpMul, OpFromBinary:
		functional = true
	}

	operands := operandExprs(args, inAssignment, gateVars)
	if functional {
		// if an operation supports infinite length of arguments,
		// turn it into a chain of operations
		switch op {
		case OpAdd, OpSub, OpMul:
			{
				finalStr := genFunctionalGate(gateVar, op, operands[0:2])
				for len(operands) > 2 {
					operands = operands[1:]
					operands[0] = getGateName(gateVar, false)
					finalStr += genFunctionalGate(gateVar, op, operands[0:2])
				}
				return finalStr
			}
		}
		return genFunctionalGate(gateVar, op, operands)
	} else if callback {
		return genCallbackGate(gateVar, op, operands)
	} else {
		return genGenericGate(op, operands)
	}
}

func genLine(app App, gateVar string, inAssignment []ExArg, gateVars []string) string {
	switch app.Op.(type) {
	case *ExGadget:
		return genGadgetCall(gateVar, inAssignment, gateVars, app.Op.(*ExGadget), app.Args)
	case Op:
		return genOpCall(gateVar, inAssignment, gateVars, app.Op.(Op), app.Args)
	}
	return ""
}

func genGadgetBody(inAssignment []ExArg, gadget ExGadget) string {
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

func operandExpr(operand Operand, inAssignment []ExArg, gateVars []string) string {
	switch operand.(type) {
	case Input:
		return inAssignment[operand.(Input).Index].Name
	case Gate:
		return gateVars[operand.(Gate).Index]
	case Proj:
		return fmt.Sprintf("%s[%d]", operandExpr(operand.(Proj).Operand, inAssignment, gateVars), operand.(Proj).Index)
	case Const:
		return operand.(Const).Value.Text(10)
	default:
		fmt.Printf("Type %T\n", operand)
		panic("not yet supported")
	}
}

func operandExprs(operands []Operand, inAssignment []ExArg, gateVars []string) []string {
	exprs := make([]string, len(operands))
	for i, operand := range operands {
		exprs[i] = operandExpr(operand, inAssignment, gateVars)
	}
	return exprs
}
