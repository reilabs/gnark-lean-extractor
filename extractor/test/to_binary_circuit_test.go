package extractor_test

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

// Example: Gadget that returns a vector
type OptimisedVectorGadget struct {
	In frontend.Variable
}

func (gadget OptimisedVectorGadget) DefineGadget(api frontend.API) interface{} {
	return api.ToBinary(gadget.In, 3)
}

// Example: ToBinary behaviour and nested Slice
type VectorGadget struct {
	In_1   []frontend.Variable
	In_2   []frontend.Variable
	Nested [][]frontend.Variable
}

func (gadget VectorGadget) DefineGadget(api frontend.API) interface{} {
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

func (circuit *ToBinaryCircuit) Define(api frontend.API) error {
	bin := api.ToBinary(circuit.In, 3)
	bout := api.ToBinary(circuit.Out, 3)

	api.Add(circuit.Double[2][2], circuit.Double[1][1], circuit.Double[0][0])
	api.Mul(bin[1], bout[1])
	d := abstractor.Call1(api, VectorGadget{circuit.Double[2][:], circuit.Double[0][:], circuit.Double})
	api.Mul(d[2], d[1])

	return nil
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
	out, err := extractor.GadgetToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}

func TestToBinaryCircuit(t *testing.T) {
	dim_1 := 3
	dim_2 := 3
	doubleSlice := make([][]frontend.Variable, dim_1)
	for i := 0; i < int(dim_1); i++ {
		doubleSlice[i] = make([]frontend.Variable, dim_2)
	}
	assignment := ToBinaryCircuit{Double: doubleSlice}
	out, err := extractor.CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}
