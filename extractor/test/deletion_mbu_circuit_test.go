package extractor_test

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/abstractor"
	"github.com/reilabs/gnark-lean-extractor/extractor"
)

// Example: Mismatched arguments error
type DeletionProof struct {
	DeletionIndices []frontend.Variable
	PreRoot         frontend.Variable
	IdComms         []frontend.Variable
	MerkleProofs    [][]frontend.Variable

	BatchSize int
	Depth     int
}

func (gadget DeletionProof) DefineGadget(api abstractor.API) interface{} {
	return gadget.PreRoot
}

type DeletionMbuCircuit struct {
	// single public input
	InputHash frontend.Variable `gnark:",public"`

	// private inputs, but used as public inputs
	DeletionIndices []frontend.Variable `gnark:"input"`
	PreRoot         frontend.Variable   `gnark:"input"`
	PostRoot        frontend.Variable   `gnark:"input"`

	// private inputs
	IdComms      []frontend.Variable   `gnark:"input"`
	MerkleProofs [][]frontend.Variable `gnark:"input"`

	BatchSize int
	Depth     int
}

func (circuit *DeletionMbuCircuit) AbsDefine(api abstractor.API) error {
	root := extractor.Call(api, DeletionProof{
		DeletionIndices: circuit.DeletionIndices,
		PreRoot:         circuit.PreRoot,
		IdComms:         circuit.IdComms,
		MerkleProofs:    circuit.MerkleProofs,
		BatchSize:       circuit.BatchSize,
		Depth:           circuit.Depth,
	})

	// Final root needs to match.
	api.AssertIsEqual(root, circuit.PostRoot)

	return nil
}

func (circuit DeletionMbuCircuit) Define(api frontend.API) error {
	return abstractor.Concretize(api, &circuit)
}

func TestDeletionMbuCircuit(t *testing.T) {
	batchSize := 2
	treeDepth := 3
	proofs := make([][]frontend.Variable, batchSize)
	for i := 0; i < int(batchSize); i++ {
		proofs[i] = make([]frontend.Variable, treeDepth)
	}

	assignment := DeletionMbuCircuit{
		DeletionIndices: make([]frontend.Variable, batchSize),
		IdComms:         make([]frontend.Variable, batchSize),
		MerkleProofs:    proofs,

		BatchSize: int(batchSize),
		Depth:     int(treeDepth),
	}
	out, err := extractor.CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}
