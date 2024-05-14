package vergo_test

import (
	"fmt"
	"github.com/reilabs/gnark-lean-extractor/v3/vergo"
	"testing"
)

func TestThisThing(t *testing.T) {
	vergo.StartExtracting()
	v1 := vergo.Uint64(*new(vergo.Vergo[uint64]).OfVar(vergo.FreeVar()))
	v2 := vergo.Uint64(*new(vergo.Vergo[uint64]).OfVar(vergo.FreeVar()))
	v3 := vergo.Add(v1, v2)
	vergo.Add(v3, v3)
	scope := vergo.StopExtracting()
	fmt.Printf("%v", scope)
	fmt.Printf("TESTANDO\n")
}
