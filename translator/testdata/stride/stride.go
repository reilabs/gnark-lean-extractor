// Package stride exercises the stride-loop form `for i := lo; i < hi; i += k`.
// Both a compile-time-constant stride and a parameter-supplied stride are
// covered.
package stride

import (
	"github.com/consensys/gnark/frontend"
)

type Stride struct {
	Xs   []frontend.Variable
	Step int
	R    frontend.Variable
}

func (c *Stride) Define(api frontend.API) error {
	// Constant stride of 2: sum every other element.
	sumEven := frontend.Variable(0)
	for i := 0; i < len(c.Xs); i += 2 {
		sumEven = api.Add(sumEven, c.Xs[i])
	}
	// Runtime stride from the Step field: sum with configurable stride.
	sumStride := frontend.Variable(0)
	for i := 0; i < len(c.Xs); i += c.Step {
		sumStride = api.Add(sumStride, c.Xs[i])
	}
	api.AssertIsEqual(api.Add(sumEven, sumStride), c.R)
	return nil
}
