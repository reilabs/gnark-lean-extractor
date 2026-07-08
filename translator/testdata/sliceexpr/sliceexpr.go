// Package sliceexpr exercises the four Go slice-expression forms.
package sliceexpr

import "github.com/consensys/gnark/frontend"

type SliceExpr struct {
	Xs [8]frontend.Variable
}

func (c *SliceExpr) Define(api frontend.API) error {
	all := c.Xs[:]
	head := c.Xs[:3]
	tail := c.Xs[5:]
	mid := c.Xs[2:6]
	api.AssertIsEqual(all[0], head[0])
	api.AssertIsEqual(tail[0], mid[3])
	return nil
}
