package extractor_test

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

type Nest1 struct {
	In1 frontend.Variable
	In2 [5]frontend.Variable
}

type Nest2 struct {
	In1 [4][4]frontend.Variable
	In2 [3]frontend.Variable
}

type NestedCircuit struct {
	N1 Nest1
	N2 Nest2
}

func (circuit *NestedCircuit) Define(api frontend.API) error {
	sum := api.Add(circuit.N1.In2[2], circuit.N2.In2[0])
	api.AssertIsEqual(sum, circuit.N1.In2[1])
	return nil
}

func TestNestedCircuit(t *testing.T) {
	circuit := NestedCircuit{}
	out, err := extractor.CircuitToLean(&circuit, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}
