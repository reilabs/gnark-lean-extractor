package extractor_test

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v2/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v2/extractor"
	"github.com/stretchr/testify/assert"
)

// Example: circuit with constant parameter
type ReturnItself struct {
	In_1 []frontend.Variable
	Out  []frontend.Variable
}

func (gadget ReturnItself) DefineGadget(api abstractor.API) interface{} {
	for i := 0; i < len(gadget.In_1); i++ {
		gadget.Out[i] = api.Mul(gadget.In_1[i], gadget.In_1[i])
	}

	return gadget.Out
}

type SliceGadget struct {
	In_1 []frontend.Variable
	In_2 []frontend.Variable
}

func (gadget SliceGadget) DefineGadget(api abstractor.API) interface{} {
	for i := 0; i < len(gadget.In_1); i++ {
		api.Mul(gadget.In_1[i], gadget.In_2[i])
	}

	r := api.FromBinary(gadget.In_1...)
	return r
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
		D = extractor.Call1(api, ReturnItself{
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
	extractor.Call(api, SliceGadget{circuit.Path, circuit.Path})

	api.Mul(circuit.Path[0], circuit.Path[0])
	extractor.Call(api, SliceGadget{circuit.Tree, circuit.Tree})
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
	out, err := extractor.CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}
