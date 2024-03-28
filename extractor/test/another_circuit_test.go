package extractor_test

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

// Example: Gadget with nested array of int
type IntArrayGadget struct {
	In           []frontend.Variable
	Matrix       [2]int
	NestedMatrix [2][2]int
}

func (gadget IntArrayGadget) DefineGadget(api frontend.API) interface{} {
	r := api.FromBinary(gadget.In...)
	api.Mul(gadget.Matrix[0], gadget.Matrix[1])
	return []frontend.Variable{r, r, r}
}

type AnotherCircuit struct {
	In     []frontend.Variable
	Matrix [2][2]int
}

func (circuit *AnotherCircuit) Define(api frontend.API) error {
	r := abstractor.Call1(api, IntArrayGadget{
		circuit.In,
		circuit.Matrix[0],
		circuit.Matrix,
	})

	api.FromBinary(r[1:3]...)
	api.FromBinary(r[0:2]...)
	api.FromBinary(r...)
	return nil
}

func TestAnotherCircuit(t *testing.T) {
	m := [2][2]int{
		{0, 36},
		{1, 44},
	}
	assignment := AnotherCircuit{
		In:     make([]frontend.Variable, 4),
		Matrix: m,
	}
	out, err := extractor.CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}
