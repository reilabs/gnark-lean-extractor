package parser_test

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v2/parser"
)

// Example: readme circuit
type MyCircuit struct {
	In_1 frontend.Variable
	In_2 frontend.Variable
	Out  frontend.Variable
}

func (circuit *MyCircuit) Define(api frontend.API) error {
	sum := api.Add(circuit.In_1, circuit.In_2)
	api.AssertIsEqual(sum, circuit.Out)
	return nil
}

func TestMyCircuit(t *testing.T) {
	assignment := MyCircuit{}
	out, err := parser.CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}
