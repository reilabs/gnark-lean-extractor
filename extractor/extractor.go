// Package extractor implements the abstractor.API to transpile a circuit from
// Golang to Lean.
// The file [extractor.go] contains the functions which populate the ExCircuit
// struct. The ExCircuit struct is used for the internal representation of the
// circuit in a format to be processed for conversion to Lean.
// The file [lean_export.go] contains the functions to generate the string
// corresponding to the gnark circuit given the ExCircuit struct.
//
// Structure of extractor:
// The single entry point to call the extractor is CircuitToLean which
// takes a pointer to a struct that implements the abstractor.Circuit interface.
// The circuit fields in the struct shall be public and of type
// frontend.Variable or slices/arrays of frontend.Variable.
// CircuitToLean uses schema.New function to scan the circuit fields to
// initialise, then processes the circuit operations by calling AbsDefine
// and finally it calls ExportCircuit to generate the Lean code.
package extractor

import (
	"fmt"
	"log"
	"math/big"
	"reflect"

	"github.com/reilabs/gnark-lean-extractor/abstractor"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

// The Operand interface marks the structures which can
// be used as operands in the circuit.
// The implementation of isOperand() for a type generally
// does nothing.
// If new Operand are added, update the case-statements of
// these functions:
// operandExpr() in lean_export.go
// sanitizeVars() in extractor.go
type Operand interface {
	isOperand()
}

// Const indicates a hard-coded constant in the circuit
type Const struct {
	Value *big.Int // underlying constant value
}

func (Const) isOperand() {}

// Gate indicates a gate in the arithmetic circuit.
// Index is sequential and it is initialised by function AddApp
type Gate struct {
	Index int // the number of the gate
}

func (Gate) isOperand() {}

// Input is used to save the position of the argument in the
// list of arguments of the circuit function. It is
// instantiated in the function CircuitInit in lean_export.go
type Input struct {
	Index int // the field number in the circuit/gadget struct
}

func (Input) isOperand() {}

// Proj is used for Array or Slice inputs which are
// extracted as Vector in Lean.
// Index is the index to be accessed in the array
// Operand[Index]
type Proj struct {
	Operand Operand
	Index   int // index of the field in the array
}

func (Proj) isOperand() {}

// ProjArray is used for nested arrays
type ProjArray struct {
	Proj []Operand
}

func (ProjArray) isOperand() {}

// The Op interface marks the structures which can
// be used as operators in the circuit.
type Op interface {
	isOp()
}

type OpKind int

const (
	OpAdd OpKind = iota
	OpMulAcc
	OpNegative
	OpSub
	OpMul
	OpDiv
	OpDivUnchecked
	OpInverse
	OpToBinary
	OpFromBinary
	OpXor
	OpOr
	OpAnd
	OpSelect
	OpLookup
	OpIsZero
	OpCmp
	OpAssertEq
	OpAssertNotEq
	OpAssertIsBool
	OpAssertLessEqual
)

func (OpKind) isOp() {}

// The struct that represents a gadget.
// It is instantiated in the function DefineGadget.
type ExGadget struct {
	Name      string // obtained from the Gadget struct name
	Arity     int    // number of gadget fields (private and public)
	Code      []App
	Outputs   []Operand
	Extractor *CodeExtractor
	Fields    []schema.Field // obtained from frontend.NewSchema
	Args      []ExArg        // list of gadget fields needed to know the right function signature in Lean
}

func (g *ExGadget) isOp() {}

// The struct which combines Operators and Operands
type App struct {
	Op   Op
	Args []Operand
}

// The array which contains the series of operations
// in a circuit or gadget
type Code struct {
	Gates []App
}

// ExArgType is used by ExArg to keep track
// of the length of nested arrays
type ExArgType struct {
	Size int
	Type *ExArgType
}

// ExArg is used to keep track of the inputs of a
// circuit or gadget. The reason we have the field
// Kind is to distinguish between an array/slice of
// length 1 and a single element. The Type field
// is to allow nested arrays of different lengths
type ExArg struct {
	Name string
	Kind reflect.Kind
	Type ExArgType
}

// ExCircuit contains the structure of the circuit
// to be fed to the function ExportCircuit in
// lean_export.go to be converted in a Lean function
type ExCircuit struct {
	Inputs  []ExArg    // list of circuit fields needed to know the right function signature in Lean
	Gadgets []ExGadget // list of gadgets used
	Code    []App      // list of circuit operations
	Field   ecc.ID     // Field of the circuit. Needed for binary operations and to know the modulo
	Name    string
}

// CodeExtractor is the object used throughout the
// DefineGadget and AbsDefine functions to add operations
// to the circuit or gadget
type CodeExtractor struct {
	Code    []App
	Gadgets []ExGadget
	Field   ecc.ID
}

// This function returns a slice with the same length as the input
// array and the same elements for each index
func arrayToSlice(array reflect.Value) []frontend.Variable {
	res := make([]frontend.Variable, array.Len())

	for i := 0; i < array.Len(); i++ {
		res[i] = array.Index(i).Elem().Interface().(frontend.Variable)
	}

	return res
}

// The call function is used under the hood to call a gadget.
// The first draft of the API required the user to first call DefineGadget
// then invoke Call on the result. This has been hidded by the creation of the
// function Call in CodeExtractor.
// Due to the fact the return type is always an array, if the gadget returns a single
// value, it will be placed in index 0
func (g *ExGadget) Call(gadget abstractor.GadgetDefinition) []frontend.Variable {
	// This function behaves like other operations
	// i.e. call AddApp and return the result of the call. The difference is
	// that arguments require some manipulation because we don't know the fields
	// of the gadget
	args := []frontend.Variable{}

	// The use of reflect is to make a list of frontend.Variable from the gadget
	// fields.
	rv := reflect.Indirect(reflect.ValueOf(gadget))
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		rf := rt.Field(i)
		v := rv.FieldByName(rf.Name)
		if v.Kind() == reflect.Slice {
			args = append(args, v.Interface().([]frontend.Variable))
		} else if v.Kind() == reflect.Array {
			// Can't convert from array to slice using Reflect because
			// the field is unaddressable so I need to create a new object
			args = append(args, arrayToSlice(v))
		} else {
			args = append(args, v.Elem().Interface().(frontend.Variable))
		}
	}

	gate := g.Extractor.addApp(g, args...)
	outs := make([]frontend.Variable, len(g.Outputs))
	if len(g.Outputs) == 1 {
		outs[0] = gate
	} else {
		for i := range g.Outputs {
			outs[i] = Proj{gate, i}
		}
	}
	return outs
}

// Single entry point to Call a gadget.
func (ce *CodeExtractor) Call(gadget abstractor.GadgetDefinition) []frontend.Variable {
	// Copying `gadget` because `DefineGadget` changes the input
	v := reflect.ValueOf(gadget)
	tmp_gadget := reflect.New(v.Type())
	tmp_gadget.Elem().Set(v)
	ex_gadget := ce.DefineGadget(tmp_gadget.Interface().(abstractor.GadgetDefinition))
	return ex_gadget.Call(gadget)
}

// This function generates the Operand struct from the list of arguments to an operation
func sanitizeVars(args ...frontend.Variable) []Operand {
	ops := []Operand{}
	for _, arg := range args {
		switch arg := arg.(type) {
		case Input, Gate, Proj, Const:
			ops = append(ops, arg.(Operand))
		case int:
			ops = append(ops, Const{big.NewInt(int64(arg))})
		case big.Int:
			casted := arg
			ops = append(ops, Const{&casted})
		case []frontend.Variable:
			// In case of nested arrays, perform a recursion
			opsArray := sanitizeVars(arg...)
			ops = append(ops, ProjArray{opsArray})
		default:
			fmt.Printf("invalid argument of type %T\n%#v\n", arg, arg)
			panic("invalid argument")
		}
	}
	return ops
}

func (ce *CodeExtractor) addApp(op Op, args ...frontend.Variable) Operand {
	app := App{op, sanitizeVars(args...)}
	ce.Code = append(ce.Code, app)
	return Gate{len(ce.Code) - 1}
}

func (ce *CodeExtractor) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return ce.addApp(OpAdd, append([]frontend.Variable{i1, i2}, in...)...)
}

func (ce *CodeExtractor) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	return ce.addApp(OpMulAcc, a, b, c)
}

func (ce *CodeExtractor) Neg(i1 frontend.Variable) frontend.Variable {
	return ce.addApp(OpNegative, i1)
}

func (ce *CodeExtractor) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return ce.addApp(OpSub, append([]frontend.Variable{i1, i2}, in...)...)
}

func (ce *CodeExtractor) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return ce.addApp(OpMul, append([]frontend.Variable{i1, i2}, in...)...)
}

// Returns i1 / i2 with i2 != 0. If i1 == i2, it returns 0
func (ce *CodeExtractor) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	return ce.addApp(OpDivUnchecked, i1, i2)
}

// Returns i1 / i2 with i2 != 0
func (ce *CodeExtractor) Div(i1, i2 frontend.Variable) frontend.Variable {
	return ce.addApp(OpDiv, i1, i2)
}

func (ce *CodeExtractor) Inverse(i1 frontend.Variable) frontend.Variable {
	return ce.addApp(OpInverse, i1)
}

// From integer to binary vector
// n is the length of the resulting vector i.e. the number of bits starting from LSB
func (ce *CodeExtractor) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	nbBits := ce.Field.ScalarField().BitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("Number of bits in ToBinary must be > 0")
		}
	}
	gate := ce.addApp(OpToBinary, i1, nbBits)
	return []frontend.Variable{gate}
}

// From binary vector to integer
func (ce *CodeExtractor) FromBinary(b ...frontend.Variable) frontend.Variable {
	// Packs in little-endian
	return ce.addApp(OpFromBinary, append([]frontend.Variable{}, b...)...)
}

func (ce *CodeExtractor) Xor(a, b frontend.Variable) frontend.Variable {
	return ce.addApp(OpXor, a, b)
}

func (ce *CodeExtractor) Or(a, b frontend.Variable) frontend.Variable {
	return ce.addApp(OpOr, a, b)
}

func (ce *CodeExtractor) And(a, b frontend.Variable) frontend.Variable {
	return ce.addApp(OpAnd, a, b)
}

// b must be 0 or 1. if b ? i1 : i2
func (ce *CodeExtractor) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	return ce.addApp(OpSelect, b, i1, i2)
}

// 4-way multiplexer
func (ce *CodeExtractor) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	return ce.addApp(OpLookup, b0, b1, i0, i1, i2, i3)
}

func (ce *CodeExtractor) IsZero(i1 frontend.Variable) frontend.Variable {
	return ce.addApp(OpIsZero, i1)
}

// i1 < i2 ? -1 : 1
func (ce *CodeExtractor) Cmp(i1, i2 frontend.Variable) frontend.Variable {
	return ce.addApp(OpCmp, i1, i2)
}

func (ce *CodeExtractor) AssertIsEqual(i1, i2 frontend.Variable) {
	ce.addApp(OpAssertEq, i1, i2)
}

func (ce *CodeExtractor) AssertIsDifferent(i1, i2 frontend.Variable) {
	ce.addApp(OpAssertNotEq, i1, i2)
}

func (ce *CodeExtractor) AssertIsBoolean(i1 frontend.Variable) {
	ce.addApp(OpAssertIsBool, i1)
}

// v <= bound
func (ce *CodeExtractor) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	ce.addApp(OpAssertLessEqual, v, bound)
}

func (ce *CodeExtractor) Println(a ...frontend.Variable) {
	panic("implement me")
}

func (ce *CodeExtractor) Compiler() frontend.Compiler {
	panic("implement me")
}

func (ce *CodeExtractor) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	panic("implement me")
}

func (ce *CodeExtractor) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	switch v := v.(type) {
	case Const:
		return v.Value, true
	case Proj:
		switch v.Operand.(type) {
		case Const:
			return v.Operand.(Const).Value, true
		default:
			return nil, false
		}
	case int64:
		return big.NewInt(v), true
	case big.Int:
		return &v, true
	default:
		return nil, false
	}
}

// Checks whether name is already present in list gadgets
func getGadgetByName(gadgets []ExGadget, name string) abstractor.Gadget {
	for _, gadget := range gadgets {
		if gadget.Name == name {
			return &gadget
		}
	}
	return nil
}

// The function DefineGadget parses gadget to generate an instance of ExGadget
// If gadget has been parsed already, it will return a pointer to the existing ExGadget.
func (ce *CodeExtractor) DefineGadget(gadget abstractor.GadgetDefinition) abstractor.Gadget {
	if reflect.ValueOf(gadget).Kind() != reflect.Ptr {
		panic("DefineGadget only takes pointers to the gadget")
	}
	schema, _ := getSchema(gadget)
	err := CircuitInit(gadget, schema)
	if err != nil {
		log.Fatal(err)
	}
	// Can't use `schema.NbPublic + schema.NbSecret`
	// for arity because each element in the array is considered
	// an additional field
	arity := len(schema.Fields)
	args := getExArgs(gadget, schema.Fields)

	// To distinguish between gadgets instantiated with different array
	// sizes, add a suffix to the name. The suffix of each instantiation
	// is made up of the concatenation of the length of all the array
	// fields in the gadget.
	// This is because the Lean circuit will use fixed size Vectors.
	suffix := ""
	for _, a := range args {
		if a.Kind == reflect.Array || a.Kind == reflect.Slice {
			suffix += fmt.Sprintf("_%d", a.Type.Size)
		}
	}
	name := fmt.Sprintf("%s%s", reflect.TypeOf(gadget).Elem().Name(), suffix)

	ptr_gadget := getGadgetByName(ce.Gadgets, name)
	if ptr_gadget != nil {
		return ptr_gadget
	}

	oldCode := ce.Code
	ce.Code = make([]App, 0)
	outputs := gadget.DefineGadget(ce)
	newCode := ce.Code
	ce.Code = oldCode
	exGadget := ExGadget{
		Name:      name,
		Arity:     arity,
		Code:      newCode,
		Outputs:   sanitizeVars(outputs...),
		Extractor: ce,
		Fields:    schema.Fields,
		Args:      args,
	}
	ce.Gadgets = append(ce.Gadgets, exGadget)
	return &exGadget
}

var _ abstractor.API = &CodeExtractor{}
