package extractor

import (
	"fmt"
	"gnark-extractor/abstractor"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// Example: circuit with constant parameter
type CircuitWithParameter struct {
	In    frontend.Variable `gnark:",public"`
	Param int
}

func (circuit *CircuitWithParameter) AbsDefine(api abstractor.API) error {
	api.AssertIsEqual(circuit.Param, circuit.In)

	return nil
}

func (circuit CircuitWithParameter) Define(api frontend.API) error {
	return abstractor.Concretize(api, &circuit)
}

func TestCircuitWithParameter(t *testing.T) {
	assignment := CircuitWithParameter{}
	assignment.Param = 20
	err := CircuitToLean(&assignment, ecc.BW6_756)
	if err != nil {
		fmt.Println("CircuitToLean error!")
		fmt.Println(err.Error())
	}
}

// Example: circuit with arrays and gadget
type Hash struct {
	In_1 frontend.Variable
	In_2 frontend.Variable
}

func (gadget Hash) GadgetDefine(api abstractor.API) []frontend.Variable {
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
	hash := api.DefineGadget(&Hash{})

	current := circuit.Element
	for i := 0; i < len(circuit.Path); i++ {
		leftHash := hash.Call(Hash{current, circuit.Proof[i]})[0]
		rightHash := hash.Call(Hash{circuit.Proof[i], current})[0]
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

func (gadget MyWidget) GadgetDefine(api abstractor.API) []frontend.Variable {
	sum := api.Add(gadget.Test_1, gadget.Test_2)
	mul := api.Mul(gadget.Test_1, gadget.Test_2)
	r := api.Div(sum, mul)
	return []frontend.Variable{r}
}

type MySecondWidget struct {
	Test_1 frontend.Variable
	Test_2 frontend.Variable
}

func (gadget MySecondWidget) GadgetDefine(api abstractor.API) []frontend.Variable {
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
