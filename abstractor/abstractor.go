package abstractor

import "github.com/consensys/gnark/frontend"

type Gadget interface {
	Call(gadget GadgetDefinition) []frontend.Variable
}

type GadgetDefinition interface {
	DefineGadget(api API) []frontend.Variable
}

type API interface {
	frontend.API
	DefineGadget(gadget GadgetDefinition) Gadget
}

type Circuit interface {
	frontend.Circuit
	AbsDefine(api API) error
}

func Concretize(api frontend.API, circuit Circuit) error {
	return circuit.AbsDefine(&Concretizer{api})
}
