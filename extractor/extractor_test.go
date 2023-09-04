package extractor

import (
	"fmt"
	"log"
	"testing"

	"github.com/reilabs/gnark-lean-extractor/abstractor"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/assert"
)

// Example: ToBinary behaviour and nested Slice
type VectorGadget struct {
	In_1 []frontend.Variable
	In_2 []frontend.Variable
}

func (gadget VectorGadget) DefineGadget(api abstractor.API) []frontend.Variable {
	var sum frontend.Variable
	for i := 0; i < len(gadget.In_1); i++ {
		sum = api.Mul(gadget.In_1[i], gadget.In_2[i])
	}
	return []frontend.Variable{sum, sum, sum}
}

type ToBinaryCircuit struct {
	In     frontend.Variable     `gnark:",public"`
	Out    frontend.Variable     `gnark:",public"`
	Double [][]frontend.Variable `gnark:",public"`
}

func (circuit *ToBinaryCircuit) AbsDefine(api abstractor.API) error {
	bin := api.ToBinary(circuit.In, 3)
	bout := api.ToBinary(circuit.Out, 3)

	api.Add(circuit.Double[2][2], circuit.Double[1][1], circuit.Double[0][0])
	api.Mul(bin[1], bout[1])
	d := api.Call(VectorGadget{circuit.Double[2][:], circuit.Double[0][:]})
	api.Mul(d[2], d[1])

	return nil
}

func (circuit ToBinaryCircuit) Define(api frontend.API) error {
	return abstractor.Concretize(api, &circuit)
}

func TestToBinaryCircuit(t *testing.T) {
	dim_1 := 3
	dim_2 := 3
	doubleSlice := make([][]frontend.Variable, dim_1)
	for i := 0; i < int(dim_1); i++ {
		doubleSlice[i] = make([]frontend.Variable, dim_2)
	}
	assignment := ToBinaryCircuit{Double: doubleSlice}
	out, err := CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}

// Example: readme circuit
type DummyCircuit struct {
	In_1 frontend.Variable
	In_2 frontend.Variable
	Out  frontend.Variable
}

func (circuit *DummyCircuit) AbsDefine(api abstractor.API) error {
	sum := api.Add(circuit.In_1, circuit.In_2)
	api.AssertIsEqual(sum, circuit.Out)
	return nil
}

func (circuit DummyCircuit) Define(api frontend.API) error {
	return abstractor.Concretize(api, &circuit)
}

func TestDummyCircuit(t *testing.T) {
	assignment := DummyCircuit{}
	out, err := CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
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
	api.FromBinary(circuit.Path...)
	bin := api.ToBinary(circuit.In)
	bin = api.ToBinary(circuit.Param)

	dec := api.FromBinary(bin...)
	api.AssertIsEqual(circuit.Param, dec)
	api.Call(SliceGadget{circuit.Path, circuit.Path})

	api.Mul(circuit.Path[0], circuit.Path[0])
	api.Call(SliceGadget{circuit.Tree, circuit.Tree})
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
	out, err := CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
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
	current := circuit.Element
	for i := 0; i < len(circuit.Path); i++ {
		leftHash := api.Call(DummyHash{current, circuit.Proof[i]})[0]
		rightHash := api.Call(DummyHash{circuit.Proof[i], current})[0]
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
	out, err := CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}

// Example: circuit with multiple gadgets
type MyWidget struct {
	Test_1 frontend.Variable
	Test_2 frontend.Variable
	Num    int
}

func (gadget MyWidget) DefineGadget(api abstractor.API) []frontend.Variable {
	sum := api.Add(gadget.Test_1, gadget.Test_2)
	mul := api.Mul(gadget.Test_1, gadget.Test_2)
	r := api.Div(sum, mul)
	api.AssertIsBoolean(gadget.Num)
	return []frontend.Variable{r}
}

type MySecondWidget struct {
	Test_1 frontend.Variable
	Test_2 frontend.Variable
	Num    int
}

func (gadget MySecondWidget) DefineGadget(api abstractor.API) []frontend.Variable {
	mul := api.Mul(gadget.Test_1, gadget.Test_2)
	snd := api.Call(MyWidget{gadget.Test_1, gadget.Test_2, gadget.Num})[0]
	r := api.Mul(mul, snd)
	return []frontend.Variable{r}
}

type TwoGadgets struct {
	In_1 frontend.Variable
	In_2 frontend.Variable
	Num  int
}

func (circuit *TwoGadgets) AbsDefine(api abstractor.API) error {
	sum := api.Add(circuit.In_1, circuit.In_2)
	prod := api.Mul(circuit.In_1, circuit.In_2)
	api.Call(MySecondWidget{sum, prod, circuit.Num})
	return nil
}

func (circuit TwoGadgets) Define(api frontend.API) error {
	return abstractor.Concretize(api, &circuit)
}

func TestTwoGadgets(t *testing.T) {
	assignment := TwoGadgets{Num: 11}
	out, err := CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}
