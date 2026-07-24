// Package copybuiltin exercises Go's `copy(dst, src)` builtin under the
// translator's value semantics: bare copy rebinds dst; copy(dst[a:b], src)
// splices src into dst's [a:b] range.
package copybuiltin

import "github.com/consensys/gnark/frontend"

type CopyBuiltin struct {
	Src [4]frontend.Variable
}

func (c *CopyBuiltin) Define(api frontend.API) error {
	dst := make([]frontend.Variable, 4)
	copy(dst, c.Src[:])
	api.AssertIsEqual(dst[0], c.Src[0])

	pt := make([]frontend.Variable, 8)
	copy(pt[0:4], c.Src[:])
	copy(pt[4:8], c.Src[:])
	api.AssertIsEqual(pt[4], c.Src[0])
	return nil
}
