package extractor

import (
	"fmt"
	"math/big"
	"reflect"
	"regexp"
	"strings"

	"github.com/reilabs/gnark-lean-extractor/abstractor"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

func isWhitespacePresent(input string) bool {
	return regexp.MustCompile(`\s`).MatchString(input)
}

func ExportPrelude(name string, order *big.Int) string {
	trimmedName := strings.TrimSpace(name)
	if isWhitespacePresent(trimmedName) {
		panic("Whitespace isn't allowed in namespace tag")
	}
	s := fmt.Sprintf(`import ProvenZk.Gates
import ProvenZk.Ext.Vector

namespace %s

set_option maxRecDepth 1200
set_option maxHeartbeats 2000000

def Order : ℕ := 0x%s
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order`, trimmedName, order.Text(16))

	return s
}

func ExportFooter(name string) string {
	trimmedName := strings.TrimSpace(name)
	if isWhitespacePresent(trimmedName) {
		panic("Whitespace isn't allowed in namespace tag")
	}
	s := fmt.Sprintf(`end %s`, trimmedName)
	return s
}

func ExportGadget(gadget ExGadget) string {
	kArgs := ""
	if len(gadget.Outputs) == 1 {
		kArgs = "(k: F -> Prop)"
	} else if len(gadget.Outputs) > 1 {
		kArgs = fmt.Sprintf("(k: Vector F %d -> Prop)", len(gadget.Outputs))
	}
	inAssignment := gadget.Args

	return fmt.Sprintf("def %s %s %s: Prop :=\n%s", gadget.Name, genArgs(inAssignment), kArgs, genGadgetBody(inAssignment, gadget))
}

func ExportGadgets(exGadgets []ExGadget) string {
	gadgets := make([]string, len(exGadgets))
	for i, gadget := range exGadgets {
		gadgets[i] = ExportGadget(gadget)
	}
	return strings.Join(gadgets, "\n\n")
}

func ExportCircuit(circuit ExCircuit, name string) string {
	gadgets := ExportGadgets(circuit.Gadgets)
	circ := fmt.Sprintf("def circuit %s: Prop :=\n%s", genArgs(circuit.Inputs), genCircuitBody(circuit))
	prelude := ExportPrelude(name, circuit.Field.ScalarField())
	footer := ExportFooter(name)
	return fmt.Sprintf("%s\n\n%s\n\n%s\n\n%s", prelude, gadgets, circ, footer)
}

func ArrayInit(f schema.Field, v reflect.Value, op Operand) error {
	for i := 0; i < f.ArraySize; i++ {
		op := Proj{op, i}
		switch len(f.SubFields) {
		case 1:
			ArrayInit(f.SubFields[0], v.Index(i), op)
		case 0:
			value := reflect.ValueOf(op)
			v.Index(i).Set(value)
		default:
			panic("Only nested arrays supported in SubFields")
		}
	}
	return nil
}

func ArrayZero(v reflect.Value) {
	switch v.Kind() {
	case reflect.Slice:
		if v.Len() != 0 {
			// Check if there are nested arrays. If yes, continue recursion
			// until most nested array
			if v.Addr().Elem().Index(0).Kind() == reflect.Slice {
				for i := 0; i < v.Len(); i++ {
					ArrayZero(v.Addr().Elem().Index(i))
				}
			} else {
				zero_array := make([]frontend.Variable, v.Len(), v.Len())
				v.Set(reflect.ValueOf(&zero_array).Elem())
			}
		}
	default:
		panic("Only nested slices supported in SubFields of slices")
	}
}

func CircuitInit(class any, schema *schema.Schema) error {
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
			ArrayInit(f, tmp.Elem().FieldByName(field_name), Input{j})
		} else if field_type.Kind() == reflect.Slice {
			// Recreate a zeroed array to remove overlapping pointers if input
			// arguments are duplicated (i.e. `api.Call(SliceGadget{circuit.Path, circuit.Path})`)
			ArrayZero(tmp.Elem().FieldByName(field_name))
			ArrayInit(f, tmp.Elem().FieldByName(field_name), Input{j})
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

func KindOfField(a any, s string) reflect.Kind {
	v := reflect.ValueOf(a).Elem()
	f := v.FieldByName(s)
	return f.Kind()
}

func CircuitArgs(field schema.Field) ExArgType {
	// Handling only subfields which are nested arrays
	switch len(field.SubFields) {
	case 1:
		subType := CircuitArgs(field.SubFields[0])
		return ExArgType{field.ArraySize, &subType}
	case 0:
		return ExArgType{field.ArraySize, nil}
	default:
		panic("Only nested arrays supported in SubFields")
	}
}

func GetExArgs(circuit any, fields []schema.Field) []ExArg {
	args := []ExArg{}
	for _, f := range fields {
		kind := KindOfField(circuit, f.Name)
		arg := ExArg{f.Name, kind, CircuitArgs(f)}
		args = append(args, arg)
	}
	return args
}

// Cloned version of NewSchema without constraints
func GetSchema(circuit any) (*schema.Schema, error) {
	tVariable := reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
	return schema.New(circuit, tVariable)
}

func getStructName(circuit any) string {
	return reflect.TypeOf(circuit).Elem().Name()
}

func CircuitToLeanWithName(circuit abstractor.Circuit, field ecc.ID, namespace string) (string, error) {
	schema, err := GetSchema(circuit)
	if err != nil {
		return "", err
	}

	err = CircuitInit(circuit, schema)
	if err != nil {
		fmt.Println("CircuitInit error!")
		fmt.Println(err.Error())
	}

	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	err = circuit.AbsDefine(&api)
	if err != nil {
		return "", err
	}

	name := getStructName(circuit)

	extractorCircuit := ExCircuit{
		Inputs:  GetExArgs(circuit, schema.Fields),
		Gadgets: api.Gadgets,
		Code:    api.Code,
		Field:   api.FieldID,
		Name:    name,
	}
	out := ExportCircuit(extractorCircuit, namespace)
	return out, nil
}

func CircuitToLean(circuit abstractor.Circuit, field ecc.ID) (string, error) {
	name := getStructName(circuit)
	return CircuitToLeanWithName(circuit, field, name)
}

func GadgetToLeanWithName(gadget abstractor.GadgetDefinition, field ecc.ID, namespace string) (string, error) {
	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	api.DefineGadget(gadget)
	gadgets := ExportGadgets(api.Gadgets)
	prelude := ExportPrelude(namespace, api.FieldID.ScalarField())
	footer := ExportFooter(namespace)
	return fmt.Sprintf("%s\n\n%s\n\n%s", prelude, gadgets, footer), nil
}

func GadgetToLean(gadget abstractor.GadgetDefinition, field ecc.ID) (string, error) {
	name := getStructName(gadget)
	return GadgetToLeanWithName(gadget, field, name)
}

func ExtractGadgets(namespace string, field ecc.ID, gadgets ...abstractor.GadgetDefinition) (string, error) {
	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	for _, gadget := range gadgets {
		api.DefineGadget(gadget)
	}

	gadgets_string := ExportGadgets(api.Gadgets)
	prelude := ExportPrelude(namespace, api.FieldID.ScalarField())
	footer := ExportFooter(namespace)
	return fmt.Sprintf("%s\n\n%s\n\n%s", prelude, gadgets_string, footer), nil
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
		for i := range arg.(ProjArray).Proj {
			res = append(res, extractGateVars(arg.(ProjArray).Proj[i])...)
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
	switch op {
	case OpFromBinary:
		is_gate := reflect.TypeOf(args[0]) == reflect.TypeOf(Gate{})
		if len(args) == 1 && is_gate {
			return fmt.Sprintf("    ∃%s, %s %s %s ∧\n", gateName, genGateOp(op), strings.Join(operands, " "), gateName)
		}
		return fmt.Sprintf("    ∃%s, %s vec![%s] %s ∧\n", gateName, genGateOp(op), strings.Join(operands, ", "), gateName)
	default:
		return fmt.Sprintf("    ∃%s, %s %s %s ∧\n", gateName, genGateOp(op), strings.Join(operands, " "), gateName)
	}
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
	outs := operandExprs(gadget.Outputs, inAssignment, gateVars)
	lastLine := "    True"
	if len(outs) != 0 {
		result := outs[0]
		if len(gadget.Outputs) > 1 {
			result = fmt.Sprintf("vec![%s]", strings.Join(outs, ", "))
		}
		lastLine = fmt.Sprintf("    k %s", result)
	}
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
	case ProjArray:
		opArray := operandExprs(operand.(ProjArray).Proj, inAssignment, gateVars)
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
	exprs := make([]string, len(operands))
	for i, operand := range operands {
		exprs[i] = operandExpr(operand, inAssignment, gateVars)
	}
	return exprs
}
