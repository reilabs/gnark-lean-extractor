// Package poseidon implements a Poseidon permutation (width 3, 8 full and 56
// partial rounds, with stand-in round constants and MDS matrix) and Merkle
// tree recovery on top of it — all as plain Go functions, no gadget structs.
package poseidon

import "github.com/consensys/gnark/frontend"

func sbox(api frontend.API, x frontend.Variable) frontend.Variable {
	x2 := api.Mul(x, x)
	x4 := api.Mul(x2, x2)
	return api.Mul(x4, x)
}

// mix multiplies the state by a stand-in MDS matrix M[i][j] = i + 2j + 1.
func mix(api frontend.API, state []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(state))
	for i := 0; i < len(state); i++ {
		acc := frontend.Variable(0)
		for j := 0; j < len(state); j++ {
			acc = api.Add(acc, api.Mul(state[j], i+2*j+1))
		}
		out[i] = acc
	}
	return out
}

// permute is the Poseidon permutation with stand-in round constants
// rc(r, j) = 3r + j + 1.
func permute(api frontend.API, state []frontend.Variable) []frontend.Variable {
	for r := 0; r < 64; r++ {
		for j := 0; j < len(state); j++ {
			state[j] = api.Add(state[j], r*len(state)+j+1)
		}
		if r < 4 || 60 <= r {
			for j := 0; j < len(state); j++ {
				state[j] = sbox(api, state[j])
			}
		} else {
			state[0] = sbox(api, state[0])
		}
		state = mix(api, state)
	}
	return state
}

// hash2 is a two-to-one compression over the permutation.
func hash2(api frontend.API, l frontend.Variable, r frontend.Variable) frontend.Variable {
	state := []frontend.Variable{0, l, r}
	state = permute(api, state)
	return state[0]
}

type MerkleRecover struct {
	Root    frontend.Variable
	Element frontend.Variable
	Path    []frontend.Variable
	Proof   []frontend.Variable
}

func (c *MerkleRecover) Define(api frontend.API) error {
	current := c.Element
	for i := 0; i < len(c.Proof); i++ {
		left := hash2(api, current, c.Proof[i])
		right := hash2(api, c.Proof[i], current)
		current = api.Select(c.Path[i], right, left)
	}
	api.AssertIsEqual(current, c.Root)
	return nil
}
