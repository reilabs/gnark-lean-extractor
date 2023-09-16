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

// Example: Gadget with nested array of int
type IntArrayGadget struct {
	In           []frontend.Variable
	Matrix       [2]int
	NestedMatrix [2][2]int
}

func (gadget IntArrayGadget) DefineGadget(api abstractor.API) []frontend.Variable {
	r := api.FromBinary(gadget.In...)
	return []frontend.Variable{r}
}

type AnotherCircuit struct {
	In     []frontend.Variable
	Matrix [2][2]int
}

func (circuit *AnotherCircuit) AbsDefine(api abstractor.API) error {
	api.Call(IntArrayGadget{
		circuit.In,
		circuit.Matrix[0],
		circuit.Matrix,
	})
	return nil
}

func (circuit AnotherCircuit) Define(api frontend.API) error {
	return abstractor.Concretize(api, &circuit)
}

func TestAnotherCircuit(t *testing.T) {
	m := [2][2]int{
		{0, 36},
		{1, 44},
	}
	assignment := AnotherCircuit{
		In:     make([]frontend.Variable, 3),
		Matrix: m,
	}
	out, err := CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}

// Example: Gadget that returns a vector
type OptimisedVectorGadget struct {
	In frontend.Variable
}

func (gadget OptimisedVectorGadget) DefineGadget(api abstractor.API) []frontend.Variable {
	return api.ToBinary(gadget.In, 3)
}

// Example: ToBinary behaviour and nested Slice
type VectorGadget struct {
	In_1   []frontend.Variable
	In_2   []frontend.Variable
	Nested [][]frontend.Variable
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
	d := api.Call(VectorGadget{circuit.Double[2][:], circuit.Double[0][:], circuit.Double})
	api.Mul(d[2], d[1])

	return nil
}

func (circuit ToBinaryCircuit) Define(api frontend.API) error {
	return abstractor.Concretize(api, &circuit)
}

func TestGadgetExtraction(t *testing.T) {
	dim_1 := 3
	dim_2 := 3
	doubleSlice := make([][]frontend.Variable, dim_1)
	for i := 0; i < int(dim_1); i++ {
		doubleSlice[i] = make([]frontend.Variable, dim_2)
	}
	assignment := VectorGadget{
		In_1:   make([]frontend.Variable, dim_2),
		In_2:   make([]frontend.Variable, dim_2),
		Nested: doubleSlice,
	}
	out, err := GadgetToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
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
type ReturnItself struct {
	In_1 []frontend.Variable
	Out  []frontend.Variable
}

func (gadget ReturnItself) DefineGadget(api abstractor.API) []frontend.Variable {
	for i := 0; i < len(gadget.In_1); i++ {
		gadget.Out[i] = api.Mul(gadget.In_1[i], gadget.In_1[i])
	}

	return gadget.Out
}

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
	D := make([]frontend.Variable, 3)
	for i := 0; i < len(circuit.Path); i++ {
		D = api.Call(ReturnItself{
			In_1: circuit.Path,
			Out:  D,
		})
		api.AssertIsEqual(D[1], D[2])
	}

	api.FromBinary(circuit.Path...)
	api.FromBinary(D...)
	api.FromBinary(D[1], D[2], D[0])
	api.FromBinary(D[1], 0, D[0])
	api.FromBinary(D[1:3]...)
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
	Num    uint32
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
	snd := api.Call(MyWidget{gadget.Test_1, gadget.Test_2, uint32(gadget.Num)})[0]
	api.Mul(mul, snd)
	return []frontend.Variable{}
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

func TestExtractGadgets(t *testing.T) {
	assignment_1 := DummyHash{}
	assignment_2 := MySecondWidget{Num: 11}
	assignment_3 := MySecondWidget{Num: 9}
	out, err := ExtractGadgets("MultipleGadgets", ecc.BN254, &assignment_1, &assignment_2, &assignment_3)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}

func TestExtractGadgetsVectors(t *testing.T) {
	dim_1 := 3
	dim_2 := 3
	doubleSlice := make([][]frontend.Variable, dim_1)
	for i := 0; i < int(dim_1); i++ {
		doubleSlice[i] = make([]frontend.Variable, dim_2)
	}
	assignment_1 := VectorGadget{
		In_1:   make([]frontend.Variable, dim_2),
		In_2:   make([]frontend.Variable, dim_2),
		Nested: doubleSlice,
	}
	assignment_2 := ReturnItself{
		In_1: make([]frontend.Variable, dim_1),
		Out:  make([]frontend.Variable, dim_1),
	}
	assignment_3 := OptimisedVectorGadget{}
	out, err := ExtractGadgets("MultipleGadgetsVectors", ecc.BN254, &assignment_1, &assignment_2, &assignment_3)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}

func TestExtractCircuits(t *testing.T) {
	assignment_1 := TwoGadgets{Num: 11}
	assignment_2 := MerkleRecover{}

	dim_1 := 3
	dim_2 := 3
	doubleSlice := make([][]frontend.Variable, dim_1)
	for i := 0; i < int(dim_1); i++ {
		doubleSlice[i] = make([]frontend.Variable, dim_2)
	}
	assignment_3 := ToBinaryCircuit{Double: doubleSlice}
	assignment_4 := TwoGadgets{Num: 6}
	assignment_5 := TwoGadgets{Num: 6}

	out, err := ExtractCircuits("MultipleCircuits", ecc.BN254, &assignment_3, &assignment_2, &assignment_1, &assignment_4, &assignment_5)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
}
