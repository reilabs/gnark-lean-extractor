package extractor_test

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v2/extractor"
)

// Example: circuit with arrays and gadget
type DummyHash struct {
	In_1 frontend.Variable
	In_2 frontend.Variable
}

func (gadget DummyHash) DefineGadget(api frontend.API) interface{} {
	r := api.Mul(gadget.In_1, gadget.In_2)
	return r
}

type MerkleRecover struct {
	Root    frontend.Variable     `gnark:",public"`
	Element frontend.Variable     `gnark:",public"`
	Path    [20]frontend.Variable `gnark:",secret"`
	Proof   [20]frontend.Variable `gnark:",secret"`
}

func (circuit *MerkleRecover) Define(api frontend.API) error {
	current := circuit.Element
	for i := 0; i < len(circuit.Path); i++ {
		leftHash := extractor.Call(api, DummyHash{current, circuit.Proof[i]})
		rightHash := extractor.Call(api, DummyHash{circuit.Proof[i], current})
		current = api.Select(circuit.Path[i], rightHash, leftHash)
	}
	api.AssertIsEqual(current, circuit.Root)

	return nil
}

func TestMerkleRecover(t *testing.T) {
	assignment := MerkleRecover{}
	out, err := extractor.CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}
