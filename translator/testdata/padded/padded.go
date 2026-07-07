// Package padded exercises make, slice writes, if/else on size conditions,
// and index+value range loops.
package padded

import "github.com/consensys/gnark/frontend"

type Padded struct {
	Xs  []frontend.Variable
	Out []frontend.Variable
	Cap int
}

func double(api frontend.API, x frontend.Variable) frontend.Variable {
	return api.Add(x, x)
}

func (c *Padded) Define(api frontend.API) error {
	buf := make([]frontend.Variable, c.Cap)
	for i := 0; i < c.Cap; i++ {
		if i < len(c.Xs) {
			buf[i] = double(api, c.Xs[i])
		} else {
			buf[i] = 0
		}
	}
	for i, v := range buf {
		api.AssertIsEqual(v, c.Out[i])
	}
	return nil
}
