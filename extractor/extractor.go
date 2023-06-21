package extractor

import (
	"fmt"
	"gnark-extractor/abstractor"
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

type Operand interface {
	isOperand()
}

type Const struct {
	Value *big.Int
}

func (_ Const) isOperand() {}

type Gate struct {
	Index int
}

func (_ Gate) isOperand() {}

type Input struct {
	Index int
}

func (_ Input) isOperand() {}

type Proj struct {
	Index   int
	Operand Operand
}

func makeProj(size int, operand Operand) []frontend.Variable {
	outs := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		outs[i] = Proj{i, operand}
	}
	return outs
}

func (_ Proj) isOperand() {}

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
}

func (g *ExGadget) isOp() {}

func (g *ExGadget) Call(args ...frontend.Variable) []frontend.Variable {
	if len(args) != g.Arity {
		panic("wrong number of arguments")
	}
	gate := g.Extractor.AddApp(g, args...)
	outs := make([]frontend.Variable, len(g.Outputs))
	if len(g.Outputs) == 1 {
		outs[0] = gate
	} else {
		for i := range g.Outputs {
			outs[i] = Proj{i, gate}
		}
	}
	return outs
}

type ExArg struct {
	Name string
	Size int
	Type reflect.Kind
}

type ExCircuit struct {
	Inputs  []ExArg
	Gadgets []ExGadget
	Code    []App
}

type CodeExtractor struct {
	Code    []App
	Gadgets []ExGadget
	Field   ecc.ID
}

func operandFromArray(arg []frontend.Variable) Operand {
	return arg[0].(Proj).Operand
}

func sanitizeVars(args ...frontend.Variable) []Operand {
	ops := make([]Operand, len(args))
	for i, arg := range args {
		switch arg.(type) {
		case Input, Gate, Proj, Const:
			ops[i] = arg.(Operand)
		case int:
			ops[i] = Const{big.NewInt(int64(arg.(int)))}
		case big.Int:
			casted := arg.(big.Int)
			ops[i] = Const{&casted}
		case []frontend.Variable:
			ops[i] = operandFromArray(arg.([]frontend.Variable))
		default:
			fmt.Printf("invalid argument of type %T\n%#v\n", arg, arg)
			panic("invalid argument")
		}
	}
	return ops
}

func (ce *CodeExtractor) AddApp(op Op, args ...frontend.Variable) Operand {
	ce.Code = append(ce.Code, App{op, sanitizeVars(args...)})
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
	nbBits := ce.Field.ScalarField().BitLen()
	if len(n) == 1 {
		nbBits = n[0]
		if nbBits < 0 {
			panic("Number of bits in ToBinary must be > 0")
		}
	}
	gate := ce.AddApp(OpToBinary, i1, nbBits)
	return []frontend.Variable{gate}
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

func (ce *CodeExtractor) DefineGadget(name string, arity int, constructor func(api abstractor.API, args ...frontend.Variable) []frontend.Variable) abstractor.Gadget {
	oldCode := ce.Code
	ce.Code = make([]App, 0)
	inputs := make([]frontend.Variable, arity)
	for i := 0; i < arity; i++ {
		inputs[i] = Input{i}
	}
	outputs := constructor(ce, inputs...)
	newCode := ce.Code
	ce.Code = oldCode
	gadget := ExGadget{
		Name:      name,
		Arity:     arity,
		Code:      newCode,
		Outputs:   sanitizeVars(outputs...),
		Extractor: ce,
	}
	ce.Gadgets = append(ce.Gadgets, gadget)
	return &gadget
}

var _ abstractor.API = &CodeExtractor{}
