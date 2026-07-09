// Package multi exercises Config.WalkPackages: the circuit lives in this
// package but calls into a foreign `helpers` subpackage. With
// WalkPackages set to the helpers path, the translator walks the helper's
// bodies structurally rather than blackboxing them.
package multi

import (
	"github.com/consensys/gnark/frontend"

	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v3/translator/testdata/multi/helpers"
)

type Multi struct {
	A frontend.Variable
	B frontend.Variable
	R frontend.Variable
}

func (c *Multi) Define(api frontend.API) error {
	// Plain cross-package function call — translated.
	m := helpers.MixIn(api, c.A, c.B)
	// Cross-package struct + method call.
	p := helpers.Pair{Lo: c.A, Hi: c.B}
	q := p.Combine(api)
	// Cross-package gadget via abstractor.Call — DefineGadget translated,
	// not axiomatized.
	d := abstractor.Call(api, helpers.DoubleGadget{X: c.A})
	sum := api.Add(m, q)
	sum = api.Add(sum, d)
	api.AssertIsEqual(sum, c.R)
	return nil
}
