package extractor

import (
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"strings"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

func isWhitespacePresent(input string) bool {
	return regexp.MustCompile(`\s`).MatchString(input)
}

func exportPrelude(name string, order *big.Int) string {
	trimmedName := strings.TrimSpace(name)
	if isWhitespacePresent(trimmedName) {
		panic("Whitespace isn't allowed in namespace tag")
	}
	s := fmt.Sprintf(`import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace %s

def Order : ℕ := 0x%s
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order`, trimmedName, order.Text(16))

	return s
}

func exportFooter(name string) string {
	trimmedName := strings.TrimSpace(name)
	if isWhitespacePresent(trimmedName) {
		panic("Whitespace isn't allowed in namespace tag")
	}
	s := fmt.Sprintf(`end %s`, trimmedName)
	return s
}

func generateCallbackType(output reflect.Value) string {
	if output.Kind() != reflect.Slice {
		return ""
	}
	if output.Index(0).Kind() == reflect.Slice {
		innerType := generateCallbackType(output.Index(0))
		return fmt.Sprintf("Vector (%s) %d", innerType, output.Len())
	}
	return fmt.Sprintf("Vector F %d", output.Len())
}

func exportGadget(gadget ExGadget) string {
	kArgs := ""
	if len(gadget.Outputs) == 1 {
		kArgs = "(k: F -> Prop)"
	} else if len(gadget.Outputs) > 1 {
		outputType := generateCallbackType(reflect.ValueOf(gadget.OutputsDeep))
		kArgs = fmt.Sprintf("(k: %s -> Prop)", outputType)
	}
	inAssignment := gadget.Args

	return fmt.Sprintf("def %s %s %s: Prop :=\n%s", gadget.Name, genArgs(inAssignment), kArgs, genGadgetBody(inAssignment, gadget))
}

func exportGadgets(exGadgets []ExGadget) string {
	gadgets := make([]string, len(exGadgets))
	for i, gadget := range exGadgets {
		gadgets[i] = exportGadget(gadget)
	}
	return strings.Join(gadgets, "\n\n")
}

func exportCircuit(circuit ExCircuit, name string) string {
	gadgets := exportGadgets(circuit.Gadgets)
	circ := fmt.Sprintf("def circuit %s: Prop :=\n%s", genArgs(circuit.Inputs), genCircuitBody(circuit))
	prelude := exportPrelude(name, circuit.Field.ScalarField())
	footer := exportFooter(name)
	return fmt.Sprintf("%s\n\n%s\n\n%s\n\n%s", prelude, gadgets, circ, footer)
}

func circuitInit(class any, schema *schema.Schema) error {
	// https://stackoverflow.com/a/49704408
	// https://stackoverflow.com/a/14162161
	// https://stackoverflow.com/a/63422049

	// The purpose of this function is to initialise the
	// struct fields with Operand interfaces for being
	// processed by the Extractor.
	v := reflect.ValueOf(class)
	if v.Type().Kind() == reflect.Ptr {
		ptr := v
		v = ptr.Elem()
	} else {
		ptr := reflect.New(reflect.TypeOf(class))
		temp := ptr.Elem()
		temp.Set(v)
	}

	tmp_c := reflect.ValueOf(&class).Elem().Elem()
	tmp := reflect.New(tmp_c.Type()).Elem()
	tmp.Set(tmp_c)
	for j, f := range schema.Fields {
		field_name := f.Name
		field := v.FieldByName(field_name)
		field_type := field.Type()

		// Can't assign an array to another array, therefore
		// initialise each element in the array

		if field_type.Kind() == reflect.Array {
			arrayInit(f, tmp.Elem().FieldByName(field_name), Input{j})
		} else if field_type.Kind() == reflect.Slice {
			// Recreate a zeroed array to remove overlapping pointers if input
			// arguments are duplicated (i.e. `api.Call(SliceGadget{circuit.Path, circuit.Path})`)
			arrayZero(tmp.Elem().FieldByName(field_name))
			arrayInit(f, tmp.Elem().FieldByName(field_name), Input{j})
		} else if field_type.Kind() == reflect.Interface {
			init := Input{j}
			value := reflect.ValueOf(init)

			tmp.Elem().FieldByName(field_name).Set(value)
		} else {
			fmt.Printf("Skipped type %s\n", field_type.Kind())
		}
	}
	return nil
}

func circuitArgs(field schema.Field) ExArgType {
	// Handling only subfields which are nested arrays
	switch len(field.SubFields) {
	case 1:
		subType := circuitArgs(field.SubFields[0])
		return ExArgType{field.ArraySize, &subType}
	case 0:
		return ExArgType{field.ArraySize, nil}
	default:
		panic("Only nested arrays supported in SubFields")
	}
}

func getExArgs(circuit any, fields []schema.Field) []ExArg {
	args := []ExArg{}
	for _, f := range fields {
		kind := kindOfField(circuit, f.Name)
		arg := ExArg{f.Name, kind, circuitArgs(f)}
		args = append(args, arg)
	}
	return args
}

// Cloned version of NewSchema without constraints
func getSchema(circuit any) (*schema.Schema, error) {
	tVariable := reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
	return schema.New(circuit, tVariable)
}

func genNestedArrays(a ExArgType) string {
	if a.Type != nil {
		return fmt.Sprintf("Vector (%s) %d", genNestedArrays(*a.Type), a.Size)
	}
	return fmt.Sprintf("Vector F %d", a.Size)
}

func genArgs(inAssignment []ExArg) string {
	args := make([]string, len(inAssignment))
	for i, in := range inAssignment {
		switch in.Kind {
		case reflect.Array, reflect.Slice:
			args[i] = fmt.Sprintf("(%s: %s)", in.Name, genNestedArrays(in.Type))
		default:
			args[i] = fmt.Sprintf("(%s: F)", in.Name)
		}
	}
	return strings.Join(args, " ")
}

func extractGateVars(arg Operand) []Operand {
	switch arg.(type) {
	case Proj:
		return extractGateVars(arg.(Proj).Operand)
	case ProjArray:
		res := []Operand{}
		for i := range arg.(ProjArray).Projs {
			res = append(res, extractGateVars(arg.(ProjArray).Projs[i])...)
		}
		return res
	default:
		return []Operand{arg}
	}
}

func assignGateVars(code []App, additional ...Operand) []string {
	gateVars := make([]string, len(code))
	for _, app := range code {
		for _, arg := range app.Args {
			bases := extractGateVars(arg)
			for _, base := range bases {
				switch base.(type) {
				case Gate:
					ix := base.(Gate).Index
					if gateVars[ix] == "" {
						gateVars[ix] = fmt.Sprintf("gate_%d", ix)
					}
				}
			}
		}
	}
	for _, out := range additional {
		outBases := extractGateVars(out)
		for _, outBase := range outBases {
			switch outBase.(type) {
			case Gate:
				ix := outBase.(Gate).Index
				if gateVars[ix] == "" {
					gateVars[ix] = fmt.Sprintf("gate_%d", ix)
				}
			}
		}
	}

	return gateVars
}

func genGadgetCall(gateVar string, inAssignment []ExArg, gateVars []string, gadget *ExGadget, args []Operand) string {
	name := gadget.Name
	operands := operandExprs(args, inAssignment, gateVars)
	binder := "∧"
	if len(gadget.Outputs) > 0 {
		binder = "fun _ =>"
		if gateVar != "" {
			binder = fmt.Sprintf("fun %s =>", gateVar)
		}
	}
	return fmt.Sprintf("    %s %s %s\n", name, strings.Join(operands, " "), binder)
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
		name = "from_binary"
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

func genCallbackGate(gateVar string, op Op, operands []string, args []Operand) string {
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
	case OpDivUnchecked, OpDiv, OpInverse, OpXor, OpOr, OpAnd, OpSelect, OpLookup, OpCmp, OpIsZero, OpToBinary, OpFromBinary:
		callback = true
	case OpAdd, OpMulAcc, OpNegative, OpSub, OpMul:
		functional = true
	}

	operands := operandExprs(args, inAssignment, gateVars)
	if op == OpFromBinary {
		// OpFromBinary takes only one argument which is represented as list of Proj. For this reason we can
		// safely wrap it in a ProjArray and call operandExpr directly.
		projArray := ProjArray{args}
		operands = []string{operandExpr(projArray, inAssignment, gateVars)}
	}

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
		default:
			return genFunctionalGate(gateVar, op, operands)
		}
	} else if callback {
		return genCallbackGate(gateVar, op, operands, args)
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

	switch len(gadget.Outputs) {
	case 0:
		lastLine := "    True"
		return strings.Join(append(lines, lastLine), "")
	case 1:
		// The case statement ensures there is index 0 (and only 0)
		result := operandExpr(gadget.Outputs[0], inAssignment, gateVars)
		lastLine := fmt.Sprintf("    k %s", result)
		return strings.Join(append(lines, lastLine), "")
	default:
		// Same trick used for OpFromBinary in genOpCall
		result := operandExpr(ProjArray{gadget.Outputs}, inAssignment, gateVars)
		lastLine := fmt.Sprintf("    k %s", result)
		return strings.Join(append(lines, lastLine), "")
	}
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

func getArgIndex(operand ProjArray) int {
	if reflect.TypeOf(operand.Projs[0]) == reflect.TypeOf(Proj{}) {
		switch op := operand.Projs[0].(Proj).Operand.(type) {
		case Input:
			return op.Index
		case Gate:
			return op.Index
		case Proj:
			return getArgIndex(ProjArray{[]Operand{op}})
		default:
			return -1
		}
	} else if (reflect.TypeOf(operand.Projs[0]) == reflect.TypeOf(ProjArray{})) {
		return getArgIndex(operand.Projs[0].(ProjArray))
	} else {
		return -1
	}
}

func checkVector(operand ProjArray, argIdx int) (bool, Operand) {
	// Check correct length
	if operand.Projs[0].(Proj).Size != len(operand.Projs) {
		return false, operand
	}

	// Check index starts at 0
	lastIndex := operand.Projs[0].(Proj).Index
	if lastIndex != 0 {
		return false, operand
	}
	// Check always same Operand
	firstOperand := operand.Projs[0].(Proj).Operand

	// Check indices are in ascending order
	// on the same argIdx
	for _, op := range operand.Projs[1:] {
		if lastIndex != op.(Proj).Index-1 {
			return false, operand
		}
		lastIndex += 1
		if firstOperand != op.(Proj).Operand {
			return false, operand
		}
	}
	return true, operand.Projs[0].(Proj).Operand
}

func getStack(operand ProjArray) []int {
	if reflect.TypeOf(operand.Projs[0]) == reflect.TypeOf(ProjArray{}) {
		return getStack(operand.Projs[0].(ProjArray))
	} else if reflect.TypeOf(operand.Projs[0]) == reflect.TypeOf(Proj{}) {
		proj := operand.Projs[0].(Proj)
		if reflect.TypeOf(proj.Operand) == reflect.TypeOf(Proj{}) {
			return append(getStack(ProjArray{[]Operand{proj.Operand}}), proj.Size)
		} else {
			return []int{proj.Size}
		}
	} else {
		return []int{}
	}
}

func expectedOperand(op Proj, argIndex Operand, indices []int) bool {
	if op.Index != indices[len(indices)-1] {
		return false
	}
	if reflect.TypeOf(op.Operand) == reflect.TypeOf(Proj{}) {
		return expectedOperand(op.Operand.(Proj), argIndex, indices[0:len(indices)-1])
	}
	return op.Operand == argIndex
}

func checkDimensions(operand ProjArray, length []int, argIndex Operand, pastIndices ...int) bool {
	if len(operand.Projs) != length[0] {
		return false
	}
	for i, p := range operand.Projs {
		if len(length[1:]) >= 1 {
			past := append(pastIndices, i)
			if !checkDimensions(p.(ProjArray), length[1:], argIndex, past...) {
				return false
			}
		} else {
			if !expectedOperand(p.(Proj), argIndex, append(pastIndices, i)) {
				return false
			}
		}
	}
	return true
}

func getFirstOperand(operand ProjArray) Operand {
	if reflect.TypeOf(operand.Projs[0]) == reflect.TypeOf(ProjArray{}) {
		return getFirstOperand(operand.Projs[0].(ProjArray))
	} else if reflect.TypeOf(operand.Projs[0]) == reflect.TypeOf(Proj{}) {
		return operand.Projs[0].(Proj)
	} else {
		fmt.Printf("getFirstOperand %+v\n", operand)
		panic("Error in getFirstOperand.")
	}
}

func getIndex(operand Operand) Operand {
	if reflect.TypeOf(operand) != reflect.TypeOf(Proj{}) {
		return operand
	}
	return getIndex(operand.(Proj).Operand)
}

func isVectorComplete(operand ProjArray) (bool, Operand) {
	if len(operand.Projs) == 0 {
		return false, operand
	}

	if reflect.TypeOf(operand.Projs[0]) == reflect.TypeOf(ProjArray{}) {
		sliceDimensions := getStack(operand) // Outermost dimension is at index 0
		if len(sliceDimensions) == 0 {
			return false, operand
		}
		firstOperand := getFirstOperand(operand)
		argIdx := getIndex(firstOperand)
		if !checkDimensions(operand, sliceDimensions, argIdx) {
			return false, operand
		}
		return true, argIdx
	}

	argIdx := getArgIndex(operand)
	if argIdx == -1 {
		return false, operand
	}

	return checkVector(operand, argIdx)
}

func operandExpr(operand Operand, inAssignment []ExArg, gateVars []string) string {
	switch operand.(type) {
	case Input:
		return inAssignment[operand.(Input).Index].Name
	case Gate:
		return gateVars[operand.(Gate).Index]
	case Proj:
		return fmt.Sprintf("%s[%d]", operandExpr(operand.(Proj).Operand, inAssignment, gateVars), operand.(Proj).Index)
	case ProjArray:
		isComplete, newOperand := isVectorComplete(operand.(ProjArray))
		if isComplete {
			return operandExpr(newOperand, inAssignment, gateVars)
		}
		opArray := operandExprs(operand.(ProjArray).Projs, inAssignment, gateVars)
		opArray = []string{strings.Join(opArray, ", ")}
		return fmt.Sprintf("vec!%s", opArray)
	case Const:
		return fmt.Sprintf("(%s:F)", operand.(Const).Value.Text(10))
	case Integer:
		return operand.(Integer).Value.Text(10)
	default:
		fmt.Printf("Type %T\n", operand)
		panic("not yet supported")
	}
}

func operandExprs(operands []Operand, inAssignment []ExArg, gateVars []string) []string {
	exprs := []string{}
	for _, operand := range operands {
		exprs = append(exprs, operandExpr(operand, inAssignment, gateVars))
	}
	return exprs
}
