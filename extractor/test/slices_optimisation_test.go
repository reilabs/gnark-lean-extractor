package extractor_test

import (
	"log"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v2/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v2/extractor"
)

// Example: checking slices optimisation
type TwoSlices struct {
	TwoDim [][]frontend.Variable
}

func (gadget TwoSlices) DefineGadget(api frontend.API) interface{} {
	return gadget.TwoDim
}

type ThreeSlices struct {
	ThreeDim [][][]frontend.Variable
}

func (gadget ThreeSlices) DefineGadget(api frontend.API) interface{} {
	return gadget.ThreeDim
}

type SlicesGadget struct {
	TwoDim   [][]frontend.Variable
	ThreeDim [][][]frontend.Variable
}

func (gadget SlicesGadget) DefineGadget(api frontend.API) interface{} {
	return append(gadget.ThreeDim[0][0], gadget.TwoDim[0]...)
}

type SlicesOptimisation struct {
	Test     frontend.Variable
	Id       []frontend.Variable
	TwoDim   [][]frontend.Variable
	ThreeDim [][][]frontend.Variable
}

func (circuit *SlicesOptimisation) Define(api frontend.API) error {
	abstractor.Call1(api, SlicesGadget{
		TwoDim:   circuit.TwoDim,
		ThreeDim: circuit.ThreeDim,
	})
	abstractor.Call1(api, SlicesGadget{
		TwoDim:   [][]frontend.Variable{circuit.TwoDim[1], circuit.TwoDim[0]},
		ThreeDim: [][][]frontend.Variable{circuit.ThreeDim[1], circuit.ThreeDim[0]},
	})
	abstractor.Call1(api, SlicesGadget{
		TwoDim:   [][]frontend.Variable{{circuit.TwoDim[1][1]}, {circuit.TwoDim[1][0]}},
		ThreeDim: [][][]frontend.Variable{circuit.ThreeDim[1], circuit.ThreeDim[0], circuit.ThreeDim[1]},
	})
	abstractor.Call1(api, SlicesGadget{
		TwoDim:   [][]frontend.Variable{circuit.TwoDim[1], {circuit.TwoDim[1][0], circuit.TwoDim[0][0], circuit.TwoDim[1][1]}},
		ThreeDim: circuit.ThreeDim,
	})
	abstractor.Call2(api, TwoSlices{
		TwoDim: circuit.TwoDim,
	})
	a := abstractor.Call3(api, ThreeSlices{
		ThreeDim: circuit.ThreeDim,
	})
	b := abstractor.Call3(api, ThreeSlices{
		ThreeDim: a,
	})
	abstractor.Call3(api, ThreeSlices{
		ThreeDim: b,
	})

	return nil
}

func TestSlicesOptimisation(t *testing.T) {
	depthOne := 2
	depthTwo := 3
	depthThree := 4
	twoSlice := make([][]frontend.Variable, depthOne)
	for i := 0; i < int(depthOne); i++ {
		twoSlice[i] = make([]frontend.Variable, depthTwo)
	}

	threeSlice := make([][][]frontend.Variable, depthOne)
	for x := 0; x < int(depthOne); x++ {
		threeSlice[x] = make([][]frontend.Variable, depthTwo)
		for y := 0; y < int(depthTwo); y++ {
			threeSlice[x][y] = make([]frontend.Variable, depthThree)
		}
	}

	assignment := SlicesOptimisation{
		Id:       make([]frontend.Variable, depthTwo),
		TwoDim:   twoSlice,
		ThreeDim: threeSlice,
	}
	out, err := extractor.CircuitToLean(&assignment, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	checkOutput(t, out)
}
