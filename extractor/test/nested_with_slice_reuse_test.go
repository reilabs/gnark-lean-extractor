package extractor_test

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v2/extractor"
)

type N1 struct {
	In1 []frontend.Variable
}

type N2 struct {
	In1 []frontend.Variable
}

type NestedReusedCircuit struct {
	N1 N1
	N2 N2
}

func (circuit *NestedReusedCircuit) Define(api frontend.API) error {
	sum := api.Add(circuit.N1.In1[0], circuit.N2.In1[0])
	api.AssertIsEqual(sum, 0)
	return nil
}

func TestNestedReusedCircuit(t *testing.T) {
	circuit := NestedReusedCircuit{}
	ins := make([]frontend.Variable, 1)
	circuit.N2.In1 = ins
	circuit.N1.In1 = ins
	out, err := extractor.CircuitToLean(&circuit, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}
