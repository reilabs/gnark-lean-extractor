package extractor

import (
	"fmt"
	"gnark-extractor/abstractor"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/assert"
)

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
	Hashes []frontend.Variable `gnark:",public"`
}

func (circuit *Semaphore) AbsDefine(api abstractor.API) error {
	// From https://github.com/semaphore-protocol/semaphore/blob/main/packages/circuits/semaphore.circom
	calculate_secret := api.DefineGadget("CalculateSecret", 2, func(api abstractor.API, args ...frontend.Variable) []frontend.Variable {
		// Dummy hash. Real circuit uses Poseidon
		r := api.Mul(args[0], args[1])
		return []frontend.Variable{r}
	})

	calculate_identity_commitment := api.DefineGadget("CalculateIdentityCommitment", 1, func(api abstractor.API, args ...frontend.Variable) []frontend.Variable {
		// Dummy hash. Real circuit uses Poseidon
		r := api.Mul(args[0], args[0])
		return []frontend.Variable{r}
	})

	calculate_nullifier_hash := api.DefineGadget("CalculateNullifierHash", 2, func(api abstractor.API, args ...frontend.Variable) []frontend.Variable {
		// Dummy hash. Real circuit uses Poseidon
		r := api.Mul(args[0], args[1])
		return []frontend.Variable{r}
	})

	secret := calculate_secret.Call(circuit.IdentityNullifier, circuit.IdentityTrapdoor)[0]
	identity_commitment := calculate_identity_commitment.Call(secret)[0]
	nullifierHash := calculate_nullifier_hash.Call(circuit.ExternalNullifier, circuit.IdentityNullifier)[0]
	api.AssertIsEqual(nullifierHash, circuit.NullifierHash) // Verify

	circuit.Hashes[0] = identity_commitment
	for i := 0; i < circuit.Levels; i++ {
		// Unrolled merkle_tree_inclusion_proof
		api.AssertIsBoolean(circuit.TreePathIndices[i])
		leftHash := api.Mul(circuit.Hashes[i], circuit.TreeSiblings[i])
		rightHash := api.Mul(circuit.TreeSiblings[i], circuit.Hashes[i])
		circuit.Hashes[i+1] = api.Select(circuit.TreePathIndices[i], rightHash, leftHash)
	}
	root := circuit.Hashes[circuit.Levels]
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
		Hashes:          make([]frontend.Variable, nLevels+1),
	}
	assert.Equal(t, len(assignment.TreePathIndices), len(assignment.TreeSiblings), "TreePathIndices and TreeSiblings must have the same length.")
	err := CircuitToLean(&assignment, ecc.BW6_756)
	if err != nil {
		fmt.Println("CircuitToLean error!")
		fmt.Println(err.Error())
	}
}

// type CircuitWithParameter struct {
// 	In    frontend.Variable `gnark:",public"`
// 	Param int
// }

// func (circuit *CircuitWithParameter) AbsDefine(api abstractor.API) error {
// 	api.AssertIsEqual(circuit.Param, circuit.In)

// 	return nil
// }

// func (circuit CircuitWithParameter) Define(api frontend.API) error {
// 	return abstractor.Concretize(api, &circuit)
// }

// func TestCircuitWithParameter(t *testing.T) {
// 	paramValue := 20
// 	assignment := CircuitWithParameter{}
// 	assignment.Param = paramValue
// 	assert.Equal(t, assignment.Param, paramValue, "assignment.Param is a const and should be 20.")
// 	err := CircuitToLean(&assignment, ecc.BW6_756)
// 	if err != nil {
// 		fmt.Println("CircuitToLean error!")
// 		fmt.Println(err.Error())
// 	}
// }

// type MerkleRecover struct {
// 	Root    frontend.Variable     `gnark:",public"`
// 	Element frontend.Variable     `gnark:",public"`
// 	Path    [20]frontend.Variable `gnark:",secret"`
// 	Proof   [20]frontend.Variable `gnark:",secret"`
// }

// func (circuit *MerkleRecover) AbsDefine(api abstractor.API) error {
// 	hash := api.DefineGadget("hash", 2, func(api abstractor.API, args ...frontend.Variable) []frontend.Variable {
// 		return []frontend.Variable{api.Mul(args[0], args[1])}
// 	})

// 	current := circuit.Element
// 	for i := 0; i < len(circuit.Path); i++ {
// 		leftHash := hash.Call(current, circuit.Proof[i])[0]
// 		rightHash := hash.Call(circuit.Proof[i], current)[0]
// 		current = api.Select(circuit.Path[i], rightHash, leftHash)
// 	}
// 	api.AssertIsEqual(current, circuit.Root)

// 	return nil
// }

// func (circuit MerkleRecover) Define(api frontend.API) error {
// 	return abstractor.Concretize(api, &circuit)
// }

// func TestMerkleRecover(t *testing.T) {
// 	assignment := MerkleRecover{}
// 	err := CircuitToLean(&assignment, ecc.BW6_756)
// 	if err != nil {
// 		fmt.Println("CircuitToLean error!")
// 		fmt.Println(err.Error())
// 	}
// }

// type TwoGadgets struct {
// 	In_1 frontend.Variable
// 	In_2 frontend.Variable
// }

// func (circuit *TwoGadgets) AbsDefine(api abstractor.API) error {
// 	my_widget := api.DefineGadget("my_widget", 2, func(api abstractor.API, args ...frontend.Variable) []frontend.Variable {
// 		sum := api.Add(args[0], args[1])
// 		mul := api.Mul(args[0], args[1])
// 		r := api.Div(sum, mul)
// 		return []frontend.Variable{r}
// 	})
// 	my_snd_widget := api.DefineGadget("my_snd_widget", 2, func(api abstractor.API, args ...frontend.Variable) []frontend.Variable {
// 		mul := api.Mul(args[0], args[1])
// 		snd := my_widget.Call(args[0], args[1])
// 		r := api.Mul(mul, snd[0])
// 		return []frontend.Variable{r}
// 	})

// 	sum := api.Add(circuit.In_1, circuit.In_2)
// 	prod := api.Mul(circuit.In_1, circuit.In_2)
// 	my_snd_widget.Call(sum, prod)

// 	return nil
// }

// func (circuit TwoGadgets) Define(api frontend.API) error {
// 	return abstractor.Concretize(api, &circuit)
// }

// func TestTwoGadgets(t *testing.T) {
// 	assignment := TwoGadgets{}
// 	err := CircuitToLean(&assignment, ecc.BW6_756)
// 	if err != nil {
// 		fmt.Println("CircuitToLean error!")
// 		fmt.Println(err.Error())
// 	}
// }
