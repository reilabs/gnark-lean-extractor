// Package opaque exercises Config.OpaqueTypes: a field whose type is a
// generic instantiation (here surfaced through an alias) becomes an
// axiomatised Lean type. The circuit passes the value to a blackboxed
// helper without ever inspecting its shape.
package opaque

import (
	"github.com/consensys/gnark/frontend"

	"github.com/reilabs/gnark-lean-extractor/v3/translator/testdata/opaque/inner"
)

// PubKey aliases a generic instantiation — the shape of `P256PublicKey` in
// zolana. The translator is told to model it opaquely.
type PubKey = inner.Wrap[frontend.Variable, frontend.Variable]

// keyDigest is blackboxed; it takes the opaque PubKey by value and returns
// a Variable, mirroring the zolana pattern where the opaque type only ever
// flows into helper axioms.
func keyDigest(api frontend.API, pk PubKey) frontend.Variable {
	// Body only exists so the package compiles; the translator sees a
	// blackbox entry for this function and never enters here.
	_ = pk
	return api.Add(0, 0)
}

type Opaque struct {
	Pub PubKey
	Sum frontend.Variable
}

func (c *Opaque) Define(api frontend.API) error {
	d := keyDigest(api, c.Pub)
	api.AssertIsEqual(d, c.Sum)
	return nil
}
