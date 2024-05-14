package extractor_test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
	"log"
	"testing"
)

type NonnativeCube[T emulated.FieldParams] struct {
	Input emulated.Element[T]
	Cubed emulated.Element[T]
}

func (gadget *NonnativeCube[T]) Define(api frontend.API) error {
	field, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	result := field.Mul(&gadget.Input, &gadget.Input)
	result = field.Mul(result, &gadget.Input)
	field.AssertIsEqual(result, &gadget.Cubed)
	return nil
}

func TestNonnativeCubeCircuit(t *testing.T) {
	circuit := NonnativeCube[emulated.BLS12381Fr]{}
	out, err := extractor.CircuitToLean(&circuit, ecc.BN254)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(out)
	checkOutput(t, out)
}
