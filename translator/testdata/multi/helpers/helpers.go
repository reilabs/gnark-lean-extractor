// Package helpers lives in a foreign package the main circuit calls into.
// It exists so the multi-package test exercises the WalkPackages path: a
// caller in one package must reach a plain function, a struct with a
// DefineGadget method, and a receiver-style method — all defined here.
package helpers

import (
	"github.com/consensys/gnark/frontend"
)

// MixIn is a plain cross-package helper: takes two Variables, returns a
// Variable.
func MixIn(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	s := api.Add(a, b)
	return api.Mul(s, s)
}

type Pair struct {
	Lo frontend.Variable
	Hi frontend.Variable
}

// Combine is a method on Pair — the receiver-based call form must survive
// the package swap.
func (p Pair) Combine(api frontend.API) frontend.Variable {
	return api.Add(p.Lo, p.Hi)
}

// DoubleGadget is a foreign gadget invoked through abstractor.Call.
type DoubleGadget struct {
	X frontend.Variable
}

func (g DoubleGadget) DefineGadget(api frontend.API) interface{} {
	return api.Mul(g.X, 2)
}
