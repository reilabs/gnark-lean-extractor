// Package abstractor defines the abstractor.API. It is based on
// frontend.API from the gnark library plus `DefineGadget`
// and `Call` functions to support Gadgets in circuits
package abstractor

import "github.com/consensys/gnark/frontend"

// The interface to Call gadgets
type Gadget interface {
	Call(gadget GadgetDefinition) []frontend.Variable
}

// The interface to define the circuit of a gadget
type GadgetDefinition interface {
	DefineGadget(api API) []frontend.Variable
}

// The abstractor.API which extends frontend.API
type API interface {
	frontend.API
	DefineGadget(gadget GadgetDefinition) Gadget

	frontend.API
	Call(gadget GadgetDefinition) []frontend.Variable
}

// The Circuit interface. AbsDefine is the function called
// to read the circuit implementation from the extractor
type Circuit interface {
	frontend.Circuit
	AbsDefine(api API) error
}

func Concretize(api frontend.API, circuit Circuit) error {
	return circuit.AbsDefine(&Concretizer{api})
}
