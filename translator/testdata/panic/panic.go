// Package panicdemo exercises Go's `panic` builtin in two shapes:
//
//   - Standalone precondition check: `if k > 8 { panic("too big") }`.
//     Translates to `if <cond> then Circuit.panic` — the branch is
//     modelled as an unreachable Circuit that makes any run through it
//     unsatisfiable.
//
//   - The `if err != nil { panic(err) }` guard around a `(T, error)`-
//     returning call. Purely Go-side plumbing — dropped by isErrCheck.
package panicdemo

import (
	"github.com/consensys/gnark/frontend"
)

// pointOrError models a call that returns a value and an error slot.
// The circuit consumes the value on the success path and drops err.
func pointOrError(api frontend.API, x frontend.Variable) (frontend.Variable, error) {
	return api.Mul(x, x), nil
}

type Panic struct {
	X frontend.Variable
	K int
	R frontend.Variable
}

func (c *Panic) Define(api frontend.API) error {
	// Standalone panic — modelled as Circuit.panic under an if.
	if c.K > 8 {
		panic("K too big")
	}
	// (T, error) plus panic(err) guard — the whole if is dropped.
	y, err := pointOrError(api, c.X)
	if err != nil {
		panic(err)
	}
	api.AssertIsEqual(y, c.R)
	return nil
}
