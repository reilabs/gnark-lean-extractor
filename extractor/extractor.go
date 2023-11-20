package extractor

import (
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/reilabs/gnark-lean-extractor/v2/abstractor"
)

type Operand interface {
	isOperand()
}

type Const struct {
	Value *big.Int
}

func (_ Const) isOperand() {}

// Integer struct is used to distinguish between a constant in
// place of a ExtractorVariable and an integer where an integer
// is the only type allowed. Integer sruct is currently only
// used for the length of the result in ToBinary function.
type Integer struct {
	Value *big.Int
}

func (_ Integer) isOperand() {}

type Gate struct {
	Index int
}

func (_ Gate) isOperand() {}

// Input is used to save the position of the argument in the
// list of arguments of the circuit function.
type Input struct {
	Index int
}

func (_ Input) isOperand() {}

// Index is the index to be accessed in the array
// Operand[Index]
// Size is a placeholder to keep track of the whole
// array size. It is essential to know if the whole
// vector or only a slice is used as function
// argument.
type Proj struct {
	Operand Operand
	Index   int
	Size    int
}

func (_ Proj) isOperand() {}

type ProjArray struct {
	Projs []Operand
}

func (_ ProjArray) isOperand() {}

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

func (_ OpKind) isOp() {}

type App struct {
	Op   Op
	Args []Operand
}

type Code struct {
	Gates []App
}

type ExGadget struct {
	Name        string
	Arity       int
	Code        []App
	OutputsFlat []Operand
	Outputs     interface{}
	Extractor   *CodeExtractor
	Fields      []ExtractorField
	Args        []ExArg
}

func (g *ExGadget) isOp() {}

func (g *ExGadget) Call(gadget abstractor.GadgetDefinition) interface{} {
	args := []ExtractorVariable{}

	rv := reflect.Indirect(reflect.ValueOf(gadget))
	rt := rv.Type()
	// Looping through the circuit fields only.
	for i := 0; i < rt.NumField(); i++ {
		fld := rt.Field(i)
		v := rv.FieldByName(fld.Name)
		switch v.Kind() {
		case reflect.Slice:
			arg := flattenSlice(v)
			if len(arg) != 0 {
				args = append(args, arg)
			}
		case reflect.Array:
			// I can't convert from array to slice using Reflect because
			// the field is unaddressable. Therefore I recreate a slice
			// with the same elements as the input array.
			arg := arrayToSlice(v)
			// Checking length != 0 because I need to keep nested slices
			// as nested slices, but not empty slices
			if len(arg) != 0 {
				args = append(args, arg)
			}
		case reflect.Interface:
			args = append(args, v.Elem().Interface().(ExtractorVariable))
		}
	}
	gate := g.Extractor.AddApp(g, args...)

	res := replaceArg(g.Outputs, gate)
	return res
}

type ExArgType struct {
	Size int
	Type *ExArgType
}

type ExArg struct {
	Name string
	Kind reflect.Kind
	Type ExArgType
}

type ExCircuit struct {
	Inputs  []ExArg
	Gadgets []ExGadget
	Code    []App
	Field   ecc.ID
}

type CodeExtractor struct {
	Code    []App
	Gadgets []ExGadget
	FieldID ecc.ID
}

type ExtractorApi interface {
	GetCode() []App
	ResetCode()
	GetGadgets() []ExGadget
	GetField() ecc.ID
}

func (ce CodeExtractor) GetCode() []App {
	return ce.Code
}

func (ce *CodeExtractor) ResetCode() {
	ce.Code = []App{}
}

func (ce CodeExtractor) GetGadgets() []ExGadget {
	return ce.Gadgets
}

func (ce CodeExtractor) GetField() ecc.ID {
	return ce.FieldID
}

func sanitizeVars(args ...ExtractorVariable) []Operand {
	ops := []Operand{}
	for _, arg := range args {
		switch arg.(type) {
		case Input, Gate, Proj, Const:
			ops = append(ops, arg.(Operand))
		case Integer:
			ops = append(ops, arg.(Operand))
		case int:
			ops = append(ops, Const{new(big.Int).SetInt64(int64(arg.(int)))})
		case int8:
			ops = append(ops, Const{new(big.Int).SetInt64(int64(arg.(int8)))})
		case int16:
			ops = append(ops, Const{new(big.Int).SetInt64(int64(arg.(int16)))})
		case int32:
			ops = append(ops, Const{new(big.Int).SetInt64(int64(arg.(int32)))})
		case int64:
			ops = append(ops, Const{new(big.Int).SetInt64(arg.(int64))})
		case uint:
			ops = append(ops, Const{new(big.Int).SetUint64(uint64(arg.(uint)))})
		case uint8:
			ops = append(ops, Const{new(big.Int).SetUint64(uint64(arg.(uint8)))})
		case uint16:
			ops = append(ops, Const{new(big.Int).SetUint64(uint64(arg.(uint16)))})
		case uint32:
			ops = append(ops, Const{new(big.Int).SetUint64(uint64(arg.(uint32)))})
		case uint64:
			ops = append(ops, Const{new(big.Int).SetUint64(arg.(uint64))})
		case big.Int:
			casted := arg.(big.Int)
			ops = append(ops, Const{&casted})
		case []ExtractorVariable:
			opsArray := sanitizeVars(arg.([]ExtractorVariable)...)
			ops = append(ops, ProjArray{opsArray})
		case nil:
			// This takes care of uninitialised fields that are
			// passed to gadgets
			ops = append(ops, Const{big.NewInt(int64(0))})
		default:
			fmt.Printf("sanitizeVars invalid argument of type %T\n%#v\n", arg, arg)
			panic("sanitizeVars invalid argument")
		}
	}
	return ops
}

// CodeExtractor implements all the functions which are needed by the extractor
// to generate Lean code

func (ce *CodeExtractor) AddApp(op Op, args ...ExtractorVariable) Operand {
	app := App{op, sanitizeVars(args...)}
	ce.Code = append(ce.Code, app)
	return Gate{len(ce.Code) - 1}
}

func (ce *CodeExtractor) Add(i1, i2 ExtractorVariable, in ...ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpAdd, append([]ExtractorVariable{i1, i2}, in...)...)
}

func (ce *CodeExtractor) MulAcc(a, b, c ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpMulAcc, a, b, c)
}

func (ce *CodeExtractor) Neg(i1 ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpNegative, i1)
}

func (ce *CodeExtractor) Sub(i1, i2 ExtractorVariable, in ...ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpSub, append([]ExtractorVariable{i1, i2}, in...)...)
}

func (ce *CodeExtractor) Mul(i1, i2 ExtractorVariable, in ...ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpMul, append([]ExtractorVariable{i1, i2}, in...)...)
}

func (ce *CodeExtractor) DivUnchecked(i1, i2 ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpDivUnchecked, i1, i2)
}

func (ce *CodeExtractor) Div(i1, i2 ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpDiv, i1, i2)
}

func (ce *CodeExtractor) Inverse(i1 ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpInverse, i1)
}

func (ce *CodeExtractor) ToBinary(i1 ExtractorVariable, n ...int) []ExtractorVariable {
	nbBits := ce.FieldID.ScalarField().BitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("Number of bits in ToBinary must be > 0")
		}
	}

	gate := ce.AddApp(OpToBinary, i1, Integer{big.NewInt(int64(nbBits))})
	outs := make([]ExtractorVariable, nbBits)
	for i := range outs {
		outs[i] = Proj{gate, i, len(outs)}
	}
	return outs
}

func (ce *CodeExtractor) FromBinary(b ...ExtractorVariable) ExtractorVariable {
	// Packs in little-endian
	if len(b) == 0 {
		panic("FromBinary has to have at least one argument!")
	}
	if reflect.TypeOf(b[0]) == reflect.TypeOf([]ExtractorVariable{}) {
		panic("Pass operators to FromBinary using ellipsis")
	}
	return ce.AddApp(OpFromBinary, append([]ExtractorVariable{}, b...)...)
}

func (ce *CodeExtractor) Xor(a, b ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpXor, a, b)
}

func (ce *CodeExtractor) Or(a, b ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpOr, a, b)
}

func (ce *CodeExtractor) And(a, b ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpAnd, a, b)
}

func (ce *CodeExtractor) Select(b ExtractorVariable, i1, i2 ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpSelect, b, i1, i2)
}

func (ce *CodeExtractor) Lookup2(b0, b1 ExtractorVariable, i0, i1, i2, i3 ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpLookup, b0, b1, i0, i1, i2, i3)
}

func (ce *CodeExtractor) IsZero(i1 ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpIsZero, i1)
}

func (ce *CodeExtractor) Cmp(i1, i2 ExtractorVariable) ExtractorVariable {
	return ce.AddApp(OpCmp, i1, i2)
}

func (ce *CodeExtractor) AssertIsEqual(i1, i2 ExtractorVariable) {
	ce.AddApp(OpAssertEq, i1, i2)
}

func (ce *CodeExtractor) AssertIsDifferent(i1, i2 ExtractorVariable) {
	ce.AddApp(OpAssertNotEq, i1, i2)
}

func (ce *CodeExtractor) AssertIsBoolean(i1 ExtractorVariable) {
	ce.AddApp(OpAssertIsBool, i1)
}

func (ce *CodeExtractor) AssertIsLessOrEqual(v ExtractorVariable, bound ExtractorVariable) {
	ce.AddApp(OpAssertLessEqual, v, bound)
}

func (ce *CodeExtractor) Field() *big.Int {
	scalarField := ce.FieldID.ScalarField()
	return new(big.Int).Set(scalarField)
}

func (ce *CodeExtractor) FieldBitLen() int {
	return ce.FieldID.ScalarField().BitLen()
}

func (ce *CodeExtractor) ConstantValue(v ExtractorVariable) (*big.Int, bool) {
	switch v.(type) {
	case Const:
		return v.(Const).Value, true
	case Proj:
		{
			switch v.(Proj).Operand.(type) {
			case Const:
				return v.(Proj).Operand.(Const).Value, true
			default:
				return nil, false
			}
		}
	case int:
		return new(big.Int).SetInt64(int64(v.(int))), true
	case int8:
		return new(big.Int).SetInt64(int64(v.(int8))), true
	case int16:
		return new(big.Int).SetInt64(int64(v.(int16))), true
	case int32:
		return new(big.Int).SetInt64(int64(v.(int32))), true
	case int64:
		return new(big.Int).SetInt64(v.(int64)), true
	case uint:
		return new(big.Int).SetUint64(uint64(v.(uint))), true
	case uint8:
		return new(big.Int).SetUint64(uint64(v.(uint8))), true
	case uint16:
		return new(big.Int).SetUint64(uint64(v.(uint16))), true
	case uint32:
		return new(big.Int).SetUint64(uint64(v.(uint32))), true
	case uint64:
		return new(big.Int).SetUint64(v.(uint64)), true
	case big.Int:
		casted := v.(big.Int)
		return &casted, true
	default:
		return nil, false
	}
}

func (ce *CodeExtractor) DefineGadget(gadget abstractor.GadgetDefinition, api frontend.API, schema *schema.Schema) abstractor.Gadget {
	if reflect.ValueOf(gadget).Kind() != reflect.Ptr {
		panic("DefineGadget only takes pointers to the gadget")
	}

	CircuitInit(gadget, schema)
	// Can't use `schema.NbPublic + schema.NbSecret`
	// for arity because each array element is considered
	// a parameter
	arity := len(schema.Fields)
	args := getExArgs(gadget, schema.Fields)

	name := generateUniqueName(gadget, args)

	ptr_gadget := getGadgetByName(ce.Gadgets, name)
	if ptr_gadget != nil {
		return ptr_gadget
	}

	oldCode := ce.Code
	ce.Code = make([]App, 0)
	outputs := gadget.DefineGadget(api)

	// Handle gadgets returning nil.
	// Without the if-statement, the nil would be replaced with (0:F)
	// due to the case in sanitizeVars
	if outputs == nil {
		outputs = []ExtractorVariable{}
	}

	// flattenSlice needs to be called only if there are nested
	// slices in order to generate a slice of Operand.
	// TODO: remove `OutputsFlat` field and use only `Outputs`
	flatOutput := []ExtractorVariable{outputs}
	vOutputs := reflect.ValueOf(outputs)
	if vOutputs.Kind() == reflect.Slice {
		flatOutput = flattenSlice(vOutputs)
	}

	newCode := ce.Code
	ce.Code = oldCode
	exGadget := ExGadget{
		Name:        name,
		Arity:       arity,
		Code:        newCode,
		OutputsFlat: sanitizeVars(flatOutput...),
		Outputs:     outputs,
		Extractor:   ce,
		Fields:      schema.Fields,
		Args:        args,
	}
	ce.Gadgets = append(ce.Gadgets, exGadget)
	return &exGadget
}
