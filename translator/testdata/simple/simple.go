// Package simple is a plain gnark circuit — no abstractor gadget structs,
// just ordinary Go functions and loops.
package simple

import "github.com/consensys/gnark/frontend"

type MerkleChain struct {
	Leaf frontend.Variable
	Path []frontend.Variable
	Root frontend.Variable
}

func hash2(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	s := api.Add(a, b)
	return api.Mul(s, s)
}

// mimc stands in for a gnark-std gadget: the test registers it as a blackbox,
// so its body is never translated.
func mimc(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.Add(a, b)
}

func (c *MerkleChain) Define(api frontend.API) error {
	h := c.Leaf
	for i := 0; i < len(c.Path); i++ {
		h = hash2(api, h, c.Path[i])
		h = mimc(api, h, c.Path[i])
	}
	sum := api.Add(h, 1)
	api.AssertIsEqual(sum, c.Root)
	return nil
}
