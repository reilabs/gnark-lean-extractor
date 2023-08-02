package extractor

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/reilabs/gnark-lean-extractor/abstractor"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

// Prelude/Header of Lean circuit file
func exportPrelude(circuit ExCircuit) string {
	prelude := fmt.Sprintf(`import ProvenZk.Gates
import ProvenZk.Ext.Vector

namespace %s

def Order : ℕ := 0x%s
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order`, circuit.Name, circuit.Field.ScalarField().Text(16))

	return prelude
}

// Footer of Lean circuit file
func exportFooter(circuit ExCircuit) string {
	footer := fmt.Sprintf(`end %s`, circuit.Name)
	return footer
}

// This function generates the string of the gadget function in Lean
func exportGadget(gadget ExGadget) string {
	kArgsType := "F"
	if len(gadget.Outputs) > 1 {
		kArgsType = fmt.Sprintf("Vector F %d", len(gadget.Outputs))
	}
	args := gadget.Args
	return fmt.Sprintf("def %s %s (k: %s -> Prop): Prop :=\n%s", gadget.Name, genArgs(args), kArgsType, genGadgetBody(args, gadget))
}

// This function generates the string of the circuit function in Lean
func exportCircuit(circuit ExCircuit) string {
	gadgets := make([]string, len(circuit.Gadgets))
	for i, gadget := range circuit.Gadgets {
		gadgets[i] = exportGadget(gadget)
	}
	circ := fmt.Sprintf("def circuit %s: Prop :=\n%s", genArgs(circuit.Inputs), genCircuitBody(circuit))
	prelude := exportPrelude(circuit)
	footer := exportFooter(circuit)
	return fmt.Sprintf("%s\n\n%s\n\n%s\n\n%s", prelude, strings.Join(gadgets, "\n\n"), circ, footer)
}

// This function initialises array elements with the operand op.
// If it's a nested array, it performs recursion.
func arrayInit(field schema.Field, array reflect.Value, op Operand) error {
	for i := 0; i < field.ArraySize; i++ {
		op := Proj{op, i}
		switch len(field.SubFields) {
		case 1:
			arrayInit(field.SubFields[0], array.Index(i), op)
		case 0:
			value := reflect.ValueOf(op)
			array.Index(i).Set(value)
		default:
			panic("Only nested arrays supported in SubFields")
		}
	}
	return nil
}

// This function initialises public fields of class
// with Input{} or Proj{} objects (for array/slice).
// The goal of this function is to make the circuit or gadget
// struct initialised for the extractor.
func CircuitInit(class any, schema *schema.Schema) error {
	// Useful answers that guided me through reflect jungle
	// https://stackoverflow.com/a/49704408
	// https://stackoverflow.com/a/14162161
	// https://stackoverflow.com/a/63422049

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
			zero_array := make([]frontend.Variable, f.ArraySize, f.ArraySize)
			tmp.Elem().FieldByName(field_name).Set(reflect.ValueOf(&zero_array).Elem())

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

// This function returns the reflect.Kind type of the
// field name in structure class
func kindOfField(class any, name string) reflect.Kind {
	v := reflect.ValueOf(class).Elem()
	f := v.FieldByName(name)
	return f.Kind()
}

// This function generates and returns the ExArgType
// for array/slice fields in the circuit or gadget struct.
func circuitArgs(field schema.Field) ExArgType {
	switch len(field.SubFields) {
	case 1:
		subType := circuitArgs(field.SubFields[0])
		return ExArgType{field.ArraySize, &subType}
	case 0:
		return ExArgType{field.ArraySize, nil}
	default:
		// Handling only subfields which are nested arrays
		panic("Only nested arrays supported in SubFields")
	}
}

// This function returns the list of ExArg given a struct
// and a list of fields.
func getExArgs(class any, fields []schema.Field) []ExArg {
	args := []ExArg{}
	for _, f := range fields {
		kind := kindOfField(class, f.Name)
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

// The entry function which takes a circuit and a field and returns the string
// of the Lean code that represents the circuit
func CircuitToLean(circuit abstractor.Circuit, field ecc.ID) (string, error) {
	schema, err := getSchema(circuit)
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
		Field:   field,
	}

	err = circuit.AbsDefine(&api)
	if err != nil {
		return "", err
	}

	name := reflect.TypeOf(circuit).Elem().Name()

	extractorCircuit := ExCircuit{
		Inputs:  getExArgs(circuit, schema.Fields),
		Gadgets: api.Gadgets,
		Code:    api.Code,
		Field:   api.Field,
		Name:    name,
	}
	out := exportCircuit(extractorCircuit)
	return out, nil
}

func genNestedArrays(arg ExArgType) string {
	if arg.Type != nil {
		return fmt.Sprintf("Vector (%s) %d", genNestedArrays(*arg.Type), arg.Size)
	}
	return fmt.Sprintf("Vector F %d", arg.Size)
}

func genArgs(inAssignment []ExArg) string {
	args := make([]string, len(inAssignment))
	for i, arg := range inAssignment {
		switch arg.Kind {
		case reflect.Array, reflect.Slice:
			// Needed to create genNestedArrays to support recursion in case of nested
			// arrays
			args[i] = fmt.Sprintf("(%s: %s)", arg.Name, genNestedArrays(arg.Type))
		default:
			args[i] = fmt.Sprintf("(%s: F)", arg.Name)
		}
	}
	return strings.Join(args, " ")
}

// This function is needed by assignGateVars to handle
// arrays and nested arrays.
// It flattens nested arrays into a single array.
func extractGateVars(op Operand) []Operand {
	switch op.(type) {
	case Proj:
		return extractGateVars(op.(Proj).Operand)
	case ProjArray:
		res := []Operand{}
		for i := range op.(ProjArray).Proj {
			res = append(res, extractGateVars(op.(ProjArray).Proj[i])...)
		}
		return res
	default:
		return []Operand{op}
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
	binder := "_"
	if gateVar != "" {
		binder = gateVar
	}
	return fmt.Sprintf("    %s %s fun %s =>\n", name, strings.Join(operands, " "), binder)
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
	case OpToBinary:
		is_const := reflect.TypeOf(args[0]) == reflect.TypeOf(Const{})
		if is_const {
			operands[0] = fmt.Sprintf("(%s:F)", operands[0])
			return fmt.Sprintf("    ∃%s, %s %s %s ∧\n", gateName, genGateOp(op), strings.Join(operands, " "), gateName)
		}
		return fmt.Sprintf("    ∃%s, %s %s %s ∧\n", gateName, genGateOp(op), strings.Join(operands, " "), gateName)
	default:
		return fmt.Sprintf("    ∃%s, %s %s %s ∧\n", gateName, genGateOp(op), strings.Join(operands, " "), gateName)
	}
}

func genGenericGate(op Op, operands []string) string {
	return fmt.Sprintf("    %s %s ∧\n", genGateOp(op), strings.Join(operands, " "))
}

// This function generates and returns the operation call (i.e. ∃gate_0, gate_0 = Gates.add In_1 In_2 ∧)
// There are three different types of operand: generic, functional and callback
// - Generic gates return a Prop
// - Functional gates return a value (ZMod N)
// - Callback gates are implemented in Lean with the out argument as the output of the function and return a Prop
// i.e. def div (a b out : ZMod N): Prop := b ≠ 0 ∧ out = a * (1 / b)
func genOpCall(gateVar string, inAssignment []ExArg, gateVars []string, op Op, args []Operand) string {
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
		// When an operation supports infinite length of arguments,
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

// This function generates the string for an operand
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
		return operand.(Const).Value.Text(10)
	default:
		fmt.Printf("Type %T\n", operand)
		panic("not yet supported")
	}
}

// This function generates the string of operands by calling operandExpr for each operand
func operandExprs(operands []Operand, inAssignment []ExArg, gateVars []string) []string {
	exprs := make([]string, len(operands))
	for i, operand := range operands {
		exprs[i] = operandExpr(operand, inAssignment, gateVars)
	}
	return exprs
}
