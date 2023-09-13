package extractor

import (
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/reilabs/gnark-lean-extractor/abstractor"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

type Operand interface {
	isOperand()
}

type Const struct {
	Value *big.Int
}

func (_ Const) isOperand() {}

// Integer struct is used to distinguish between a constant in
// place of a frontend.Variable and an integer where an integer
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
type Proj struct {
	Operand Operand
	Index   int
}

func (_ Proj) isOperand() {}

type ProjArray struct {
	Proj []Operand
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
	Name      string
	Arity     int
	Code      []App
	Outputs   []Operand
	Extractor *CodeExtractor
	Fields    []schema.Field
	Args      []ExArg
}

func (g *ExGadget) isOp() {}

func arrayToSlice(v reflect.Value) []frontend.Variable {
	if v.Len() == 0 {
		return []frontend.Variable{}
	}

	switch v.Index(0).Kind() {
	case reflect.Array:
		args := []frontend.Variable{}
		for i := 0; i < v.Len(); i++ {
			args = append(args, arrayToSlice(v.Index(i)))
		}
		return args
	case reflect.Interface:
		res := make([]frontend.Variable, v.Len())
		for i := 0; i < v.Len(); i++ {
			res[i] = v.Index(i).Elem().Interface().(frontend.Variable)
		}
		return res
	default:
		return []frontend.Variable{}
	}
}

// flattenSlice takes a slice and returns a single dimension
// slice of frontend.Variable. This is needed to transform
// nested slices into single dimensional slices to be
// processed by sanitizeVars.
func flattenSlice(value reflect.Value) []frontend.Variable {
	if value.Len() == 0 {
		return []frontend.Variable{}
	}
	if value.Index(0).Kind() == reflect.Slice {
		args := []frontend.Variable{}
		for i := 0; i < value.Len(); i++ {
			args = append(args, flattenSlice(value.Index(i)))
		}
		return args
	}
	return value.Interface().([]frontend.Variable)
}

func (g *ExGadget) Call(gadget abstractor.GadgetDefinition) []frontend.Variable {
	args := []frontend.Variable{}

	rv := reflect.Indirect(reflect.ValueOf(gadget))
	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		fld := rt.Field(i)
		v := rv.FieldByName(fld.Name)
		switch v.Kind() {
		case reflect.Slice:
			args = append(args, flattenSlice(v))
		case reflect.Array:
			// I can't convert from array to slice using Reflect because
			// the field is unaddressable.
			args = append(args, arrayToSlice(v))
		case reflect.Interface:
			args = append(args, v.Elem().Interface().(frontend.Variable))
		}
	}

	gate := g.Extractor.AddApp(g, args...)
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

func cloneGadget(gadget abstractor.GadgetDefinition) abstractor.GadgetDefinition {
	v := reflect.ValueOf(gadget)
	tmp_gadget := reflect.New(v.Type())
	tmp_gadget.Elem().Set(v)
	return tmp_gadget.Interface().(abstractor.GadgetDefinition)
}

func (ce *CodeExtractor) Call(gadget abstractor.GadgetDefinition) []frontend.Variable {
	// Copying `gadget` because `DefineGadget` needs to manipulate the input
	clonedGadget := cloneGadget(gadget)
	g := ce.DefineGadget(clonedGadget)
	return g.Call(gadget)
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
	Name    string
}

type CodeExtractor struct {
	Code    []App
	Gadgets []ExGadget
	FieldID ecc.ID
}

func sanitizeVars(args ...frontend.Variable) []Operand {
	ops := []Operand{}
	for _, arg := range args {
		switch arg.(type) {
		case Input, Gate, Proj, Const:
			ops = append(ops, arg.(Operand))
		case Integer:
			ops = append(ops, arg.(Operand))
		case int:
			ops = append(ops, Const{big.NewInt(int64(arg.(int)))})
		case big.Int:
			casted := arg.(big.Int)
			ops = append(ops, Const{&casted})
		case []frontend.Variable:
			opsArray := sanitizeVars(arg.([]frontend.Variable)...)
			ops = append(ops, ProjArray{opsArray})
		case nil:
			// This takes care of uninitialised fields that are
			// passed to gadgets
			ops = append(ops, Const{big.NewInt(int64(0))})
		default:
			fmt.Printf("invalid argument of type %T\n%#v\n", arg, arg)
			panic("invalid argument")
		}
	}
	return ops
}

func (ce *CodeExtractor) AddApp(op Op, args ...frontend.Variable) Operand {
	app := App{op, sanitizeVars(args...)}
	ce.Code = append(ce.Code, app)
	return Gate{len(ce.Code) - 1}
}

func (ce *CodeExtractor) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return ce.AddApp(OpAdd, append([]frontend.Variable{i1, i2}, in...)...)
}

func (ce *CodeExtractor) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	return ce.AddApp(OpMulAcc, a, b, c)
}

func (ce *CodeExtractor) Neg(i1 frontend.Variable) frontend.Variable {
	return ce.AddApp(OpNegative, i1)
}

func (ce *CodeExtractor) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return ce.AddApp(OpSub, append([]frontend.Variable{i1, i2}, in...)...)
}

func (ce *CodeExtractor) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return ce.AddApp(OpMul, append([]frontend.Variable{i1, i2}, in...)...)
}

func (ce *CodeExtractor) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	return ce.AddApp(OpDivUnchecked, i1, i2)
}

func (ce *CodeExtractor) Div(i1, i2 frontend.Variable) frontend.Variable {
	return ce.AddApp(OpDiv, i1, i2)
}

func (ce *CodeExtractor) Inverse(i1 frontend.Variable) frontend.Variable {
	return ce.AddApp(OpInverse, i1)
}

func (ce *CodeExtractor) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	nbBits := ce.FieldID.ScalarField().BitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("Number of bits in ToBinary must be > 0")
		}
	}

	gate := ce.AddApp(OpToBinary, i1, Integer{big.NewInt(int64(nbBits))})
	outs := make([]frontend.Variable, nbBits)
	for i := range outs {
		outs[i] = Proj{gate, i}
	}
	return outs
}

func (ce *CodeExtractor) FromBinary(b ...frontend.Variable) frontend.Variable {
	// Packs in little-endian
	return ce.AddApp(OpFromBinary, append([]frontend.Variable{}, b...)...)
}

func (ce *CodeExtractor) Xor(a, b frontend.Variable) frontend.Variable {
	return ce.AddApp(OpXor, a, b)
}

func (ce *CodeExtractor) Or(a, b frontend.Variable) frontend.Variable {
	return ce.AddApp(OpOr, a, b)
}

func (ce *CodeExtractor) And(a, b frontend.Variable) frontend.Variable {
	return ce.AddApp(OpAnd, a, b)
}

func (ce *CodeExtractor) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	return ce.AddApp(OpSelect, b, i1, i2)
}

func (ce *CodeExtractor) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	return ce.AddApp(OpLookup, b0, b1, i0, i1, i2, i3)
}

func (ce *CodeExtractor) IsZero(i1 frontend.Variable) frontend.Variable {
	return ce.AddApp(OpIsZero, i1)
}

func (ce *CodeExtractor) Cmp(i1, i2 frontend.Variable) frontend.Variable {
	return ce.AddApp(OpCmp, i1, i2)
}

func (ce *CodeExtractor) AssertIsEqual(i1, i2 frontend.Variable) {
	ce.AddApp(OpAssertEq, i1, i2)
}

func (ce *CodeExtractor) AssertIsDifferent(i1, i2 frontend.Variable) {
	ce.AddApp(OpAssertNotEq, i1, i2)
}

func (ce *CodeExtractor) AssertIsBoolean(i1 frontend.Variable) {
	ce.AddApp(OpAssertIsBool, i1)
}

func (ce *CodeExtractor) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	ce.AddApp(OpAssertLessEqual, v, bound)
}

func (ce *CodeExtractor) Println(a ...frontend.Variable) {
	panic("implement me")
}

func (ce *CodeExtractor) Compiler() frontend.Compiler {
	return ce
}

func (ce *CodeExtractor) MarkBoolean(v frontend.Variable) {
	panic("implement me")
}

func (ce *CodeExtractor) IsBoolean(v frontend.Variable) bool {
	panic("implement me")
}

func (ce *CodeExtractor) Field() *big.Int {
	scalarField := ce.FieldID.ScalarField()
	return new(big.Int).Set(scalarField)
}

func (ce *CodeExtractor) FieldBitLen() int {
	return ce.FieldID.ScalarField().BitLen()
}

func (ce *CodeExtractor) Commit(...frontend.Variable) (frontend.Variable, error) {
	panic("implement me")
}

func (ce *CodeExtractor) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	panic("implement me")
}

func (ce *CodeExtractor) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	switch v.(type) {
	case Const:
		return v.(Const).Value, true
	case Proj:
		switch v.(Proj).Operand.(type) {
		case Const:
			return v.(Proj).Operand.(Const).Value, true
		default:
			return nil, false
		}
	case int64:
		return big.NewInt(v.(int64)), true
	case big.Int:
		casted := v.(big.Int)
		return &casted, true
	default:
		return nil, false
	}
}

func getGadgetByName(gadgets []ExGadget, name string) abstractor.Gadget {
	for _, gadget := range gadgets {
		if gadget.Name == name {
			return &gadget
		}
	}
	return nil
}

func getSize(elem ExArgType) []string {
	if elem.Type == nil {
		return []string{fmt.Sprintf("%d", elem.Size)}
	}
	return append(getSize(*elem.Type), fmt.Sprintf("%d", elem.Size))
}

func (ce *CodeExtractor) DefineGadget(gadget abstractor.GadgetDefinition) abstractor.Gadget {
	if reflect.ValueOf(gadget).Kind() != reflect.Ptr {
		panic("DefineGadget only takes pointers to the gadget")
	}
	schema, _ := GetSchema(gadget)
	CircuitInit(gadget, schema)
	// Can't use `schema.NbPublic + schema.NbSecret`
	// for arity because each array element is considered
	// a parameter
	arity := len(schema.Fields)
	args := GetExArgs(gadget, schema.Fields)

	// To distinguish between gadgets instantiated with different array
	// sizes, add a suffix to the name. The suffix of each instantiation
	// is made up of the concatenation of the length of all the array
	// fields in the gadget
	suffix := ""
	for _, a := range args {
		if a.Kind == reflect.Array || a.Kind == reflect.Slice {
			suffix += "_"
			suffix += strings.Join(getSize(a.Type), "_")
		}
	}

	val := reflect.ValueOf(gadget).Elem()
	for i := 0; i < val.NumField(); i++ {
		typeField := val.Field(i).Kind()
		if typeField == reflect.Int ||
			typeField == reflect.Int8 ||
			typeField == reflect.Int16 ||
			typeField == reflect.Int32 ||
			typeField == reflect.Int64 {
			suffix += fmt.Sprintf("_%d", val.Field(i).Int())
		} else if typeField == reflect.Uint ||
			typeField == reflect.Uint8 ||
			typeField == reflect.Uint16 ||
			typeField == reflect.Uint32 ||
			typeField == reflect.Uint64 {
			suffix += fmt.Sprintf("_%d", val.Field(i).Uint())
		} else if typeField == reflect.Uintptr ||
			typeField == reflect.Float32 ||
			typeField == reflect.Float64 ||
			typeField == reflect.Complex64 ||
			typeField == reflect.Complex128 {
			fmt.Printf("-- Gadget name doesn't differentiate yet between different initialised values of type %+v.\n", typeField)
			fmt.Print("-- Proceed with caution\n", typeField)
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
