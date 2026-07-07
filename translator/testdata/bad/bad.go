// Package bad contains circuits that compile as Go but must be REJECTED by
// the translator: each Define exercises one divergence between Go's aliasing
// semantics and the functional translation.
package bad

import "github.com/consensys/gnark/frontend"

// LoopBound reassigns a variable its loop bound reads: Go re-evaluates the
// bound each iteration, the translation evaluates it once.
type LoopBound struct {
	Xs []frontend.Variable
}

func (c *LoopBound) Define(api frontend.API) error {
	n := len(c.Xs)
	for i := 0; i < n; i++ {
		n = n - 1
		api.AssertIsBoolean(c.Xs[i])
	}
	return nil
}

// RangeWrite writes elements of a slice while ranging over it: Go iterates
// the backing array, so later iterations see the writes.
type RangeWrite struct {
	Xs []frontend.Variable
}

func (c *RangeWrite) Define(api frontend.API) error {
	xs := make([]frontend.Variable, len(c.Xs))
	for _, v := range xs {
		xs[0] = api.Add(v, 1)
	}
	api.AssertIsBoolean(xs[0])
	return nil
}

// Alias binds a slice from an existing one: Go element writes through either
// name are visible through the other.
type Alias struct {
	Xs []frontend.Variable
}

func (c *Alias) Define(api frontend.API) error {
	ys := c.Xs
	ys[0] = api.Add(ys[0], 1)
	api.AssertIsBoolean(ys[0])
	return nil
}

// writeFirst mutates its parameter's backing array — visible to Go callers,
// invisible in the translation.
func writeFirst(api frontend.API, xs []frontend.Variable) {
	xs[0] = api.Add(xs[0], 1)
}

// id returns its parameter: the result aliases the argument's backing array.
func id(api frontend.API, xs []frontend.Variable) []frontend.Variable {
	api.AssertIsBoolean(xs[0])
	return xs
}

// ReturnAlias binds an alias-returning result to a different name: ys and xs
// share a backing array in Go but are independent lists in the translation.
type ReturnAlias struct {
	Xs []frontend.Variable
}

func (c *ReturnAlias) Define(api frontend.API) error {
	xs := make([]frontend.Variable, len(c.Xs))
	ys := id(api, xs)
	ys[0] = api.Add(ys[0], 1)
	api.AssertIsEqual(ys[0], xs[0])
	return nil
}

// writeInto writes elements of its first parameter.
func writeInto(api frontend.API, dst []frontend.Variable, src []frontend.Variable) []frontend.Variable {
	dst[0] = api.Add(src[0], 1)
	return dst
}

// SameArg passes the same slice into a writing call twice: Go's writeInto
// sees dst's writes through src, the translation's does not.
type SameArg struct {
	Xs []frontend.Variable
}

func (c *SameArg) Define(api frontend.API) error {
	xs := make([]frontend.Variable, 2)
	xs = writeInto(api, xs, xs)
	api.AssertIsBoolean(xs[0])
	return nil
}

// DirtyArg passes a slice to writeFirst without the rebinding form.
type DirtyArg struct {
	Xs []frontend.Variable
}

func (c *DirtyArg) Define(api frontend.API) error {
	writeFirst(api, c.Xs)
	api.AssertIsBoolean(c.Xs[0])
	return nil
}
