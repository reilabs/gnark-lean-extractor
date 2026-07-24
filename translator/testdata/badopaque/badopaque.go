// Package badopaque contains circuits that must be REJECTED because they
// interact with opaque types in ways that would silently produce wrong Lean.
// Each Define exercises one of the three opaque-related rejection paths.
package badopaque

import (
	"github.com/consensys/gnark/frontend"
)

// Two named types that the test's OpaqueTypes map pins to distinct Lean
// opaque names — the classifier treats them as opaques even though their
// underlying representation is a struct.
type Foo struct{ X frontend.Variable }
type Bar struct{ X frontend.Variable }

// FieldOnOpaque projects a Go field out of an opaque-typed value. Rejected
// because opaque types have no fields in Lean.
type FieldOnOpaque struct {
	P Foo
	R frontend.Variable
}

func (c *FieldOnOpaque) Define(api frontend.API) error {
	api.AssertIsEqual(c.P.X, c.R)
	return nil
}

// OpaqueToOpaque converts between two distinct opaque types. Rejected
// because there's no coercion in Lean between distinct axiomatised types.
type OpaqueToOpaque struct {
	P Foo
}

func (c *OpaqueToOpaque) Define(api frontend.API) error {
	q := Bar(c.P)
	_ = q
	return nil
}

// OpaqueLiteral builds a composite literal of an opaque type. Rejected
// because opaque types have no fields to initialise.
type OpaqueLiteral struct {
	X frontend.Variable
	Y frontend.Variable
}

func (c *OpaqueLiteral) Define(api frontend.API) error {
	p := Foo{X: c.X}
	_ = p
	return nil
}
