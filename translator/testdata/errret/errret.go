// Package errret exercises the `(T, error)` special-case: Go helpers whose
// signature ends in `error` have their trailing result treated as Go-side
// plumbing — the Lean signature drops it, `v, err := helper(...)` binds only
// `v`, and the surrounding `if err != nil { return ... }` guard is dropped.
package errret

import "github.com/consensys/gnark/frontend"

type Errret struct {
	A frontend.Variable
	B frontend.Variable
	C frontend.Variable
	D frontend.Variable
}

// assertEq returns error; the error slot is Go-side plumbing.
func assertEq(api frontend.API, a, b frontend.Variable) error {
	api.AssertIsEqual(a, b)
	return nil
}

// doubled returns (Variable, error); the error slot is Go-side plumbing.
func doubled(api frontend.API, x frontend.Variable) (frontend.Variable, error) {
	return api.Add(x, x), nil
}

// split returns (Variable, Variable) — a plain two-value return, no error.
func split(api frontend.API, x frontend.Variable) (frontend.Variable, frontend.Variable) {
	return api.Add(x, 1), api.Sub(x, 1)
}

// combine exercises the caller pattern from defineMerge: `v, err := helper(…)`
// followed by `if err != nil { return nil, err }`, then a plain tuple
// destructure of a non-error multi-return.
func combine(api frontend.API, a, b frontend.Variable) (frontend.Variable, error) {
	da, err := doubled(api, a)
	if err != nil {
		return nil, err
	}
	db, err := doubled(api, b)
	if err != nil {
		return nil, err
	}
	lo, hi := split(api, api.Add(da, db))
	return api.Mul(lo, hi), nil
}

func (c *Errret) Define(api frontend.API) error {
	assertEq(api, c.A, c.B)
	out, err := combine(api, c.C, c.D)
	if err != nil {
		return err
	}
	api.AssertIsEqual(out, c.A)
	return nil
}
