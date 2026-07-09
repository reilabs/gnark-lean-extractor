// Package bigint exercises the math/big peepholes. *big.Int classifies as
// Lean's Int (arbitrary-precision); the Int→F coercion is inserted where
// the value flows into a Variable slot, not at the peephole itself.
//
//   - big.NewInt(x)                        → (x : Int)  (or `(x).toInt` for a runtime int64)
//   - new(big.Int).Lsh(big.NewInt(1), k)   → 1 * 2 ^ k  at Int kind
//   - new(big.Int).Rsh(big.NewInt(N), k)   → N / 2 ^ k  at Int kind
//   - integer shifts `1<<j`                → Int64.shiftLeft
//
// These mirror the zolana `full_field_compare.go` / `poseidon_kdf.go`
// idioms for computing per-byte scaling coefficients that eventually
// reach an api.Add / api.Mul boundary.
package bigint

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

type BigInt struct {
	X frontend.Variable
	K int
	R frontend.Variable
}

func (c *BigInt) Define(api frontend.API) error {
	coeffConst := big.NewInt(5)
	coeffShift := new(big.Int).Lsh(big.NewInt(1), uint(c.K))

	coeffRsh := new(big.Int).Rsh(big.NewInt(1024), uint(c.K))
	coeffMix := big.NewInt(int64(1 << uint(c.K)))
	sum := api.Add(
		api.Mul(c.X, coeffConst),
		api.Add(api.Add(coeffShift, coeffRsh), coeffMix),
	)
	api.AssertIsEqual(sum, c.R)
	return nil
}
