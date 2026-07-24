// Package compound exercises loop conditions of the form
// `i < hi && <residual>`. The zolana AES CTR loop iterates over full
// blocks with a short tail whose length is bounded by both the block
// size (16) and the remaining plaintext length — modelled here as an
// outer stride loop plus an inner compound-condition loop.
package compound

import (
	"github.com/consensys/gnark/frontend"
)

type Compound struct {
	Xs []frontend.Variable
	R  frontend.Variable
}

func (c *Compound) Define(api frontend.API) error {
	acc := frontend.Variable(0)
	for offset := 0; offset < len(c.Xs); offset += 4 {
		// Compound condition: process at most 4 elements per block, and
		// stop early on the final short block.
		for j := 0; j < 4 && offset+j < len(c.Xs); j++ {
			acc = api.Add(acc, c.Xs[offset+j])
		}
	}
	api.AssertIsEqual(acc, c.R)
	return nil
}
