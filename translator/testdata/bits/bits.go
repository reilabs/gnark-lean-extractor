// Package bits exercises ToBinary, range loops, mutable accumulators, and
// Go-integer parameters used as symbolic loop bounds.
package bits

import "github.com/consensys/gnark/frontend"

type BitsCircuit struct {
	In  frontend.Variable
	Sum frontend.Variable
	N   int
}

func (c *BitsCircuit) Define(api frontend.API) error {
	bits := api.ToBinary(c.In, 8)
	acc := frontend.Variable(0)
	for _, b := range bits {
		api.AssertIsBoolean(b)
		acc = api.Add(acc, b)
	}
	for i := 0; i < c.N; i++ {
		api.AssertIsBoolean(bits[i])
	}
	api.AssertIsEqual(acc, c.Sum)
	return nil
}
