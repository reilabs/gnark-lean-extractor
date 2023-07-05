package extractor

import (
	"fmt"
	"gnark-extractor/abstractor"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/assert"
)

// Example: Semaphore circuit
type DummyPoseidon struct {
	In_1 frontend.Variable
	In_2 frontend.Variable
}

func (gadget DummyPoseidon) DefineGadget(api abstractor.API) []frontend.Variable {
	// Dummy hash. Real circuit uses Poseidon
	r := api.Mul(gadget.In_1, gadget.In_2)
	return []frontend.Variable{r}
}

type MerkleTreeInclusionProof struct {
	Leaf        frontend.Variable
	PathIndices []frontend.Variable
	Siblings    []frontend.Variable
}

func (gadget MerkleTreeInclusionProof) DefineGadget(api abstractor.API) []frontend.Variable {
	// Dummy hash. Real circuit uses Poseidon
	dummy_poseidon := api.DefineGadget(&DummyPoseidon{})

	levels := len(gadget.PathIndices)
	hashes := make([]frontend.Variable, levels+1)
	hashes[0] = gadget.Leaf

	for i := 0; i < levels; i++ {
		// Unrolled merkle_tree_inclusion_proof
		api.AssertIsBoolean(gadget.PathIndices[i])
		leftHash := dummy_poseidon.Call(DummyPoseidon{hashes[i], gadget.Siblings[i]})[0]  // Dummy hash. Real circuit uses Poseidon
		rightHash := dummy_poseidon.Call(DummyPoseidon{gadget.Siblings[i], hashes[i]})[0] // Dummy hash. Real circuit uses Poseidon
		hashes[i+1] = api.Select(gadget.PathIndices[i], rightHash, leftHash)
	}
	root := hashes[levels]
	return []frontend.Variable{root}
}

type CalculateSecret struct {
	IdentityNullifier frontend.Variable
	IdentityTrapdoor  frontend.Variable
}

func (gadget CalculateSecret) DefineGadget(api abstractor.API) []frontend.Variable {
	// Dummy hash. Real circuit uses Poseidon
	r := api.Mul(gadget.IdentityNullifier, gadget.IdentityTrapdoor)
	return []frontend.Variable{r}
}

type CalculateIdentityCommitment struct {
	Secret frontend.Variable
}

func (gadget CalculateIdentityCommitment) DefineGadget(api abstractor.API) []frontend.Variable {
	// Dummy hash. Real circuit uses Poseidon
	r := api.Mul(gadget.Secret, gadget.Secret)
	return []frontend.Variable{r}
}

type CalculateNullifierHash struct {
	IdentityNullifier frontend.Variable
	ExternalNullifier frontend.Variable
}

func (gadget CalculateNullifierHash) DefineGadget(api abstractor.API) []frontend.Variable {
	// Dummy hash. Real circuit uses Poseidon
	r := api.Mul(gadget.IdentityNullifier, gadget.ExternalNullifier)
	return []frontend.Variable{r}
}

type Semaphore struct {
	IdentityNullifier frontend.Variable   `gnark:",secret"`
	IdentityTrapdoor  frontend.Variable   `gnark:",secret"`
	TreePathIndices   []frontend.Variable `gnark:",secret"` // 0 | 1
	TreeSiblings      []frontend.Variable `gnark:",secret"`

	SignalHash        frontend.Variable `gnark:",public"`
	ExternalNullifier frontend.Variable `gnark:",public"`

	// Outputs to check
	NullifierHash frontend.Variable `gnark:",public"`
	MTRoot        frontend.Variable `gnark:",public"`

	// Working values
	Levels int
}

func (circuit *Semaphore) AbsDefine(api abstractor.API) error {
	// From https://github.com/semaphore-protocol/semaphore/blob/main/packages/circuits/semaphore.circom
	calculate_secret := api.DefineGadget(&CalculateSecret{})
	calculate_identity_commitment := api.DefineGadget(&CalculateIdentityCommitment{})
	calculate_nullifier_hash := api.DefineGadget(&CalculateNullifierHash{})
	merkle_tree_inclusion_proof := api.DefineGadget(&MerkleTreeInclusionProof{
		PathIndices: make([]frontend.Variable, circuit.Levels),
		Siblings:    make([]frontend.Variable, circuit.Levels),
	})

	secret := calculate_secret.Call(CalculateSecret{circuit.IdentityNullifier, circuit.IdentityTrapdoor})[0]
	identity_commitment := calculate_identity_commitment.Call(CalculateIdentityCommitment{secret})[0]
	nullifierHash := calculate_nullifier_hash.Call(CalculateNullifierHash{circuit.ExternalNullifier, circuit.IdentityNullifier})[0]
	api.AssertIsEqual(nullifierHash, circuit.NullifierHash) // Verify

	root := merkle_tree_inclusion_proof.Call(MerkleTreeInclusionProof{
		Leaf:        identity_commitment,
		PathIndices: circuit.TreePathIndices,
		Siblings:    circuit.TreeSiblings,
	})[0]

	api.AssertIsEqual(root, circuit.MTRoot) // Verify
	api.Mul(circuit.SignalHash, circuit.SignalHash)

	return nil
}

func (circuit Semaphore) Define(api frontend.API) error {
	return abstractor.Concretize(api, &circuit)
}

func TestSemaphore(t *testing.T) {
	nLevels := 3
	assignment := Semaphore{
		Levels:          nLevels,
		TreePathIndices: make([]frontend.Variable, nLevels),
		TreeSiblings:    make([]frontend.Variable, nLevels),
	}
	assert.Equal(t, len(assignment.TreePathIndices), len(assignment.TreeSiblings), "TreePathIndices and TreeSiblings must have the same length.")
	err := CircuitToLean(&assignment, ecc.BW6_756)
	if err != nil {
		fmt.Println("CircuitToLean error!")
		fmt.Println(err.Error())
	}
}

// Example: circuit with constant parameter
type SliceGadget struct {
	In_1 []frontend.Variable
	In_2 []frontend.Variable
}

func (gadget SliceGadget) DefineGadget(api abstractor.API) []frontend.Variable {
	for i := 0; i < len(gadget.In_1); i++ {
		api.Mul(gadget.In_1[i], gadget.In_2[i])
	}

	r := api.FromBinary(gadget.In_1...)
	return []frontend.Variable{r}
}

type CircuitWithParameter struct {
	In    frontend.Variable   `gnark:",public"`
	Path  []frontend.Variable `gnark:",public"`
	Tree  []frontend.Variable `gnark:",public"`
	Param int
}

func (circuit *CircuitWithParameter) AbsDefine(api abstractor.API) error {
	slice_3 := api.DefineGadget(&SliceGadget{
		In_1: make([]frontend.Variable, 3),
		In_2: make([]frontend.Variable, 3),
	})

	slice_2 := api.DefineGadget(&SliceGadget{
		In_1: make([]frontend.Variable, 2),
		In_2: make([]frontend.Variable, 2),
	})

	api.FromBinary(circuit.Path...)
	bin := api.ToBinary(circuit.In)
	bin = api.ToBinary(circuit.Param)

	dec := api.FromBinary(bin...)
	api.AssertIsEqual(circuit.Param, dec)
	slice_3.Call(SliceGadget{circuit.Path, circuit.Path})

	api.Mul(circuit.Path[0], circuit.Path[0])
	slice_2.Call(SliceGadget{circuit.Tree, circuit.Tree})
	api.AssertIsEqual(circuit.Param, circuit.In)

	return nil
}

func (circuit CircuitWithParameter) Define(api frontend.API) error {
	return abstractor.Concretize(api, &circuit)
}

func TestCircuitWithParameter(t *testing.T) {
	paramValue := 20
	assignment := CircuitWithParameter{Path: make([]frontend.Variable, 3), Tree: make([]frontend.Variable, 2)}
	assignment.Param = paramValue
	assert.Equal(t, assignment.Param, paramValue, "assignment.Param is a const and should be 20.")
	err := CircuitToLean(&assignment, ecc.BW6_756)
	if err != nil {
		fmt.Println("CircuitToLean error!")
		fmt.Println(err.Error())
	}
}

// Example: circuit with arrays and gadget
type DummyHash struct {
	In_1 frontend.Variable
	In_2 frontend.Variable
}

func (gadget DummyHash) DefineGadget(api abstractor.API) []frontend.Variable {
	r := api.Mul(gadget.In_1, gadget.In_2)
	return []frontend.Variable{r}
}

type MerkleRecover struct {
	Root    frontend.Variable     `gnark:",public"`
	Element frontend.Variable     `gnark:",public"`
	Path    [20]frontend.Variable `gnark:",secret"`
	Proof   [20]frontend.Variable `gnark:",secret"`
}

func (circuit *MerkleRecover) AbsDefine(api abstractor.API) error {
	hash := api.DefineGadget(&DummyHash{})

	current := circuit.Element
	for i := 0; i < len(circuit.Path); i++ {
		leftHash := hash.Call(DummyHash{current, circuit.Proof[i]})[0]
		rightHash := hash.Call(DummyHash{circuit.Proof[i], current})[0]
		current = api.Select(circuit.Path[i], rightHash, leftHash)
	}
	api.AssertIsEqual(current, circuit.Root)

	return nil
}

func (circuit MerkleRecover) Define(api frontend.API) error {
	return abstractor.Concretize(api, &circuit)
}

func TestMerkleRecover(t *testing.T) {
	assignment := MerkleRecover{}
	err := CircuitToLean(&assignment, ecc.BW6_756)
	if err != nil {
		fmt.Println("CircuitToLean error!")
		fmt.Println(err.Error())
	}
}

// Example: circuit with multiple gadgets
type MyWidget struct {
	Test_1 frontend.Variable
	Test_2 frontend.Variable
}

func (gadget MyWidget) DefineGadget(api abstractor.API) []frontend.Variable {
	sum := api.Add(gadget.Test_1, gadget.Test_2)
	mul := api.Mul(gadget.Test_1, gadget.Test_2)
	r := api.Div(sum, mul)
	return []frontend.Variable{r}
}

type MySecondWidget struct {
	Test_1 frontend.Variable
	Test_2 frontend.Variable
}

func (gadget MySecondWidget) DefineGadget(api abstractor.API) []frontend.Variable {
	my_widget := api.DefineGadget(&MyWidget{})

	mul := api.Mul(gadget.Test_1, gadget.Test_2)
	snd := my_widget.Call(MyWidget{gadget.Test_1, gadget.Test_2})[0]
	r := api.Mul(mul, snd)
	return []frontend.Variable{r}
}

type TwoGadgets struct {
	In_1 frontend.Variable
	In_2 frontend.Variable
}

func (circuit *TwoGadgets) AbsDefine(api abstractor.API) error {
	my_snd_widget := api.DefineGadget(&MySecondWidget{})

	sum := api.Add(circuit.In_1, circuit.In_2)
	prod := api.Mul(circuit.In_1, circuit.In_2)
	my_snd_widget.Call(MySecondWidget{sum, prod})

	return nil
}

func (circuit TwoGadgets) Define(api frontend.API) error {
	return abstractor.Concretize(api, &circuit)
}

func TestTwoGadgets(t *testing.T) {
	assignment := TwoGadgets{}
	err := CircuitToLean(&assignment, ecc.BW6_756)
	if err != nil {
		fmt.Println("CircuitToLean error!")
		fmt.Println(err.Error())
	}
}
