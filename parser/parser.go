package parser

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v2/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v2/extractor"
)

// `CodeParser` implements the frontend.API as required by consensys/gnark
type CodeParser struct {
	ext extractor.CodeExtractor
}

// Keep GetExtractor for easy chaining of extractors
func GetExtractor(field ecc.ID) CodeParser {
	return CodeParser{ext: extractor.GetExtractor(field)}
}

func (ce *CodeParser) Call(gadget abstractor.GadgetDefinition) interface{} {
	// Deep copying `gadget` because `DefineGadget` needs to modify the gadget fields.
	// This was done as a replacement to the initial method of declaring gadgets using
	// a direct call to `Define Gadget` within the circuit and then calling GadgetDefinition.Call
	clonedGadget := extractor.CloneGadget(gadget)
	g := ce.DefineGadget(clonedGadget)
	return g.Call(gadget)
}

func (ce *CodeParser) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return ce.ext.Add(i1, i2, in...)
}

func (ce *CodeParser) MulAcc(a, b, c frontend.Variable) frontend.Variable {
	return ce.ext.MulAcc(a, b, c)
}

func (ce *CodeParser) Neg(i1 frontend.Variable) frontend.Variable {
	return ce.ext.Neg(i1)
}

func (ce *CodeParser) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return ce.ext.Sub(i1, i2, in...)
}

func (ce *CodeParser) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return ce.ext.Mul(i1, i2, in...)
}

func (ce *CodeParser) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	return ce.ext.DivUnchecked(i1, i2)
}

func (ce *CodeParser) Div(i1, i2 frontend.Variable) frontend.Variable {
	return ce.ext.Div(i1, i2)
}

func (ce *CodeParser) Inverse(i1 frontend.Variable) frontend.Variable {
	return ce.ext.Inverse(i1)
}

func (ce *CodeParser) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	return ce.ext.ToBinary(i1, n...)
}

func (ce *CodeParser) FromBinary(b ...frontend.Variable) frontend.Variable {
	return ce.ext.FromBinary(b...)
}

func (ce *CodeParser) Xor(a, b frontend.Variable) frontend.Variable {
	return ce.ext.Xor(a, b)
}

func (ce *CodeParser) Or(a, b frontend.Variable) frontend.Variable {
	return ce.ext.Or(a, b)
}

func (ce *CodeParser) And(a, b frontend.Variable) frontend.Variable {
	return ce.ext.And(a, b)
}

func (ce *CodeParser) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	return ce.ext.Select(b, i1, i2)
}

func (ce *CodeParser) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	return ce.ext.Lookup2(b0, b1, i0, i1, i2, i3)
}

func (ce *CodeParser) IsZero(i1 frontend.Variable) frontend.Variable {
	return ce.ext.IsZero(i1)
}

func (ce *CodeParser) Cmp(i1, i2 frontend.Variable) frontend.Variable {
	return ce.ext.Cmp(i1, i2)
}

func (ce *CodeParser) AssertIsEqual(i1, i2 frontend.Variable) {
	ce.ext.AssertIsEqual(i1, i2)
}

func (ce *CodeParser) AssertIsDifferent(i1, i2 frontend.Variable) {
	ce.ext.AssertIsDifferent(i1, i2)
}

func (ce *CodeParser) AssertIsBoolean(i1 frontend.Variable) {
	ce.ext.AssertIsBoolean(i1)
}

func (ce *CodeParser) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	ce.ext.AssertIsLessOrEqual(v, bound)
}

func (ce *CodeParser) Println(a ...frontend.Variable) {
	// ce.ext.Println(a...)
	panic("Not implemented")
}

func (ce *CodeParser) Compiler() frontend.Compiler {
	// return ce.ext.Compiler()
	panic("Not implemented")
}

func (ce *CodeParser) MarkBoolean(v frontend.Variable) {
	// ce.ext.MarkBoolean(v)
	panic("Not implemented")
}

func (ce *CodeParser) IsBoolean(v frontend.Variable) bool {
	// return ce.ext.IsBoolean(v)
	panic("Not implemented")
}

func (ce *CodeParser) Field() *big.Int {
	return ce.ext.Field()
}

func (ce *CodeParser) FieldBitLen() int {
	return ce.ext.FieldBitLen()
}

func (ce *CodeParser) Commit(v ...frontend.Variable) (frontend.Variable, error) {
	// return ce.ext.Commit(v...)
	panic("Not implemented")
}

func (ce *CodeParser) NewHint(f hint.Function, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	// return ce.ext.NewHint(f, nbOutputs, inputs...)
	panic("Not implemented")
}

func (ce *CodeParser) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	return ce.ext.ConstantValue(v)
}

func (ce *CodeParser) DefineGadget(gadget abstractor.GadgetDefinition) abstractor.Gadget {
	schema, _ := getSchema(gadget)
	return ce.ext.DefineGadget(gadget, ce, schema)
}
