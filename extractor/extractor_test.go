package extractor

import (
	"fmt"
	"gnark-extractor/abstractor"
	"testing"

	"github.com/consensys/gnark/frontend"
)

type MerkleRecover struct {
	Root    frontend.Variable    `gnark:",public"`
	Element frontend.Variable    `gnark:",public"`
	Path    [20]frontend.Variable `gnark:",secret"`
	Proof   [20]frontend.Variable `gnark:",secret"`
}

func (circuit *MerkleRecover) AbsDefine(api abstractor.API) error {
	hash := api.DefineGadget("hash", 2, func(api abstractor.API, args ...frontend.Variable) []frontend.Variable {
		return []frontend.Variable{api.Mul(args[0], args[1])}
	})

	Root := frontend.Variable(Input{0})
	Element := frontend.Variable(Input{1})

	// Operand corresponds to the position of the argument in the
	// list of arguments of the circuit function
	// Index is the index to be accessed

	Path := makeProj(20, Input{2})
	Proof := makeProj(20, Input{3})

	current := Element
	for i := 0; i < len(Path); i++ {
		leftHash := hash.Call(current, Proof[i])[0]
		rightHash := hash.Call(Proof[i], current)[0]
		current = api.Select(Path[i], rightHash, leftHash)
	}
	api.AssertIsEqual(current, Root)

	return nil
}

func (circuit MerkleRecover) Define(api frontend.API) error {
	return nil
}

func TestMerkleRecover(t *testing.T) {
	assignment := MerkleRecover{}
	err := CircuitToLean(&assignment)
	if err != nil {
		fmt.Println("CircuitToLean error!")
		fmt.Println(err.Error())
	}
}

type TwoGadgets struct {
	In_1 frontend.Variable
	In_2 frontend.Variable
}

func (circuit *TwoGadgets) AbsDefine(api abstractor.API) error {
	my_widget := api.DefineGadget("my_widget", 2, func(api abstractor.API, args ...frontend.Variable) []frontend.Variable {
		sum := api.Add(args[0], args[1])
		mul := api.Mul(args[0], args[1])
		r := api.Div(sum, mul)
		return []frontend.Variable{r}
	})
	my_snd_widget := api.DefineGadget("my_snd_widget", 2, func(api abstractor.API, args ...frontend.Variable) []frontend.Variable {
		mul := api.Mul(args[0], args[1])
		snd := my_widget.Call(args[0], args[1])
		r := api.Mul(mul, snd[0])
		return []frontend.Variable{r}
	})

	In_1 := Input{0}
	In_2 := Input{1}

	sum := api.Add(In_1, In_2)
	prod := api.Mul(In_1, In_2)
	my_snd_widget.Call(sum, prod)

	return nil
}

func (circuit TwoGadgets) Define(api frontend.API) error {
	return nil
}

func TestTwoGadgets(t *testing.T) {
	assignment := TwoGadgets{}
	err := CircuitToLean(&assignment)
	if err != nil {
		fmt.Println("CircuitToLean error!")
		fmt.Println(err.Error())
	}
}