package abstractor

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

type ConcreteGadget struct {
	api API
}

func (g *ConcreteGadget) Call(gadget GadgetDefinition) []frontend.Variable {
	return gadget.DefineGadget(g.api)
}

type Concretizer struct {
	api frontend.API
}

func (c *Concretizer) Add(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return c.api.Add(i1, i2, in...)
}

func (c *Concretizer) MulAcc(a, b, c_ frontend.Variable) frontend.Variable {
	return c.api.MulAcc(a, b, c_)
}

func (c *Concretizer) Neg(i1 frontend.Variable) frontend.Variable {
	return c.api.Neg(i1)
}

func (c *Concretizer) Sub(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return c.api.Sub(i1, i2, in...)
}

func (c *Concretizer) Mul(i1, i2 frontend.Variable, in ...frontend.Variable) frontend.Variable {
	return c.api.Mul(i1, i2, in...)
}

func (c *Concretizer) DivUnchecked(i1, i2 frontend.Variable) frontend.Variable {
	return c.api.DivUnchecked(i1, i2)
}

func (c *Concretizer) Div(i1, i2 frontend.Variable) frontend.Variable {
	return c.api.Div(i1, i2)
}

func (c *Concretizer) Inverse(i1 frontend.Variable) frontend.Variable {
	return c.api.Inverse(i1)
}

func (c *Concretizer) ToBinary(i1 frontend.Variable, n ...int) []frontend.Variable {
	return c.api.ToBinary(i1, n...)
}

func (c *Concretizer) FromBinary(b ...frontend.Variable) frontend.Variable {
	return c.api.FromBinary(b...)
}

func (c *Concretizer) Xor(a, b frontend.Variable) frontend.Variable {
	return c.api.Xor(a, b)
}

func (c *Concretizer) Or(a, b frontend.Variable) frontend.Variable {
	return c.api.Or(a, b)
}

func (c *Concretizer) And(a, b frontend.Variable) frontend.Variable {
	return c.api.And(a, b)
}

func (c *Concretizer) Select(b frontend.Variable, i1, i2 frontend.Variable) frontend.Variable {
	return c.api.Select(b, i1, i2)
}

func (c *Concretizer) Lookup2(b0, b1 frontend.Variable, i0, i1, i2, i3 frontend.Variable) frontend.Variable {
	return c.api.Lookup2(b0, b1, i0, i1, i2, i3)
}

func (c *Concretizer) IsZero(i1 frontend.Variable) frontend.Variable {
	return c.api.IsZero(i1)
}

func (c *Concretizer) Cmp(i1, i2 frontend.Variable) frontend.Variable {
	return c.api.Cmp(i1, i2)
}

func (c *Concretizer) AssertIsEqual(i1, i2 frontend.Variable) {
	c.api.AssertIsEqual(i1, i2)
}

func (c *Concretizer) AssertIsDifferent(i1, i2 frontend.Variable) {
	c.api.AssertIsDifferent(i1, i2)
}

func (c *Concretizer) AssertIsBoolean(i1 frontend.Variable) {
	c.api.AssertIsBoolean(i1)
}

func (c *Concretizer) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	c.api.AssertIsLessOrEqual(v, bound)
}

func (c *Concretizer) Println(a ...frontend.Variable) {
	c.api.Println(a...)
}

func (c *Concretizer) Compiler() frontend.Compiler {
	return c.api.Compiler()
}

func (c *Concretizer) NewHint(f solver.Hint, nbOutputs int, inputs ...frontend.Variable) ([]frontend.Variable, error) {
	return c.api.NewHint(f, nbOutputs, inputs...)
}

func (c *Concretizer) ConstantValue(v frontend.Variable) (*big.Int, bool) {
	return c.api.ConstantValue(v)
}

func (c *Concretizer) DefineGadget(gadget GadgetDefinition) Gadget {
	return &ConcreteGadget{c}
}

func (c *Concretizer) Call(gadget GadgetDefinition) []frontend.Variable {
	return c.DefineGadget(gadget).Call(gadget)
}

var _ API = &(Concretizer{})
