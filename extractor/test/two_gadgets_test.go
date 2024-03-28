package extractor_test

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

// Example: circuit with multiple gadgets
type MyWidget struct {
	Test_1 frontend.Variable
	Test_2 frontend.Variable
	Num    uint32
}

func (gadget MyWidget) DefineGadget(api frontend.API) interface{} {
	sum := api.Add(gadget.Test_1, gadget.Test_2)
	mul := api.Mul(gadget.Test_1, gadget.Test_2)
	r := api.Div(sum, mul)
	api.AssertIsBoolean(gadget.Num)
	return r
}

type MySecondWidget struct {
	Test_1 frontend.Variable
	Test_2 frontend.Variable
	Num    int
}

func (gadget MySecondWidget) DefineGadget(api frontend.API) interface{} {
	mul := api.Mul(gadget.Test_1, gadget.Test_2)
	snd := abstractor.Call(api, MyWidget{gadget.Test_1, gadget.Test_2, uint32(gadget.Num)})
	api.Mul(mul, snd)
	return nil
}

type TwoGadgets struct {
	In_1 frontend.Variable
	In_2 frontend.Variable
	Num  int
}

func (circuit *TwoGadgets) Define(api frontend.API) error {
	sum := api.Add(circuit.In_1, circuit.In_2)
	prod := api.Mul(circuit.In_1, circuit.In_2)
	abstractor.CallVoid(api, MySecondWidget{sum, prod, circuit.Num})
	return nil
}

func TestTwoGadgets(t *testing.T) {
	assignment := TwoGadgets{Num: 11}
	out, err := extractor.CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}

func TestExtractGadgets(t *testing.T) {
	assignment_1 := DummyHash{}
	assignment_2 := MySecondWidget{Num: 11}
	assignment_3 := MySecondWidget{Num: 9}
	out, err := extractor.ExtractGadgets("MultipleGadgets", ecc.BN254, &assignment_1, &assignment_2, &assignment_3)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
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
	out, err := extractor.ExtractGadgets("MultipleGadgetsVectors", ecc.BN254, &assignment_1, &assignment_2, &assignment_3)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
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

	out, err := extractor.ExtractCircuits("MultipleCircuits", ecc.BN254, &assignment_3, &assignment_2, &assignment_1, &assignment_4, &assignment_5)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}
