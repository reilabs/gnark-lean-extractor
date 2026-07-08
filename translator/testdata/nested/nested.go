// Package nested exercises struct-valued circuit inputs, methods on struct
// receivers, and helpers that take and return structs — the shape zolana's
// SPP circuits rely on.
package nested

import "github.com/consensys/gnark/frontend"

type Utxo struct {
	Owner frontend.Variable
	Asset frontend.Variable
}

type Public struct {
	Root frontend.Variable
}

type Nested struct {
	Public Public
	Inputs [2]Utxo
	Extra  frontend.Variable
}

// Hash is a method on Utxo returning a Variable — the receiver is threaded
// as a Lean `self` binder and callers use dot syntax.
func (u Utxo) Hash(api frontend.API) frontend.Variable {
	return api.Add(u.Owner, u.Asset)
}

// bumpAsset takes and returns a Utxo, using a keyed composite literal.
func bumpAsset(api frontend.API, u Utxo) Utxo {
	return Utxo{Owner: u.Owner, Asset: api.Add(u.Asset, 1)}
}

func (c *Nested) Define(api frontend.API) error {
	api.AssertIsEqual(c.Public.Root, c.Extra)
	for i := 0; i < len(c.Inputs); i++ {
		h := c.Inputs[i].Hash(api)
		u := bumpAsset(api, c.Inputs[i])
		api.AssertIsEqual(h, u.Asset)
	}
	return nil
}
