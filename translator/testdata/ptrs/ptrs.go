// Package ptrs exercises the pointer-op erasure: `&x` and `*p` on value types
// are the syntactic noise gnark helpers use to pass value records to helpers;
// the translation is value-semantic so these render as identities.
package ptrs

import "github.com/consensys/gnark/frontend"

type Point struct {
	X frontend.Variable
	Y frontend.Variable
}

// takePoint takes a pointer and reads through it. Callers pass `&pt`, the
// translation erases the reference.
func takePoint(api frontend.API, p *Point) frontend.Variable {
	return api.Add(p.X, p.Y)
}

// makePoint returns a pointer; callers dereference with `*makePoint(...)`.
func makePoint(api frontend.API, x, y frontend.Variable) *Point {
	return &Point{X: x, Y: y}
}

type Ptrs struct {
	A frontend.Variable
	B frontend.Variable
}

func (c *Ptrs) Define(api frontend.API) error {
	pt := Point{X: c.A, Y: c.B}
	h := takePoint(api, &pt)
	q := *makePoint(api, c.A, c.B)
	api.AssertIsEqual(h, api.Add(q.X, q.Y))
	return nil
}
