// Package gadget exercises the abstractor convention: gadget structs whose
// DefineGadget method carries the semantics, wrapped in abstractor.Call /
// CallVoid / Call1 at the call site. The translator rewrites each call as a
// direct method invocation on the gadget value.
package gadget

import (
	"github.com/consensys/gnark/frontend"

	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// SumGadget returns a single Variable — canonical `abstractor.Call` target.
type SumGadget struct {
	A frontend.Variable
	B frontend.Variable
}

func (g SumGadget) DefineGadget(api frontend.API) interface{} {
	return api.Add(g.A, g.B)
}

// AssertBoolGadget returns nothing usable — canonical `CallVoid` target. It
// returns an empty slice because the abstractor's Go path needs a concrete
// type; on the Lean side we just discard.
type AssertBoolGadget struct {
	X frontend.Variable
}

func (g AssertBoolGadget) DefineGadget(api frontend.API) interface{} {
	api.AssertIsBoolean(g.X)
	return []frontend.Variable{}
}

// PairGadget returns a two-element []Variable — canonical `Call1` target.
type PairGadget struct {
	X frontend.Variable
}

func (g PairGadget) DefineGadget(api frontend.API) interface{} {
	return []frontend.Variable{g.X, api.Mul(g.X, g.X)}
}

type Gadget struct {
	A frontend.Variable
	B frontend.Variable
}

func (c *Gadget) Define(api frontend.API) error {
	s := abstractor.Call(api, SumGadget{A: c.A, B: c.B})
	abstractor.CallVoid(api, AssertBoolGadget{X: c.A})
	pair := abstractor.Call1(api, PairGadget{X: c.B})
	api.AssertIsEqual(s, pair[0])
	return nil
}
