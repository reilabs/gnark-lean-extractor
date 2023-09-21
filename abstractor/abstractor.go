package abstractor

import "github.com/consensys/gnark/frontend"

type Gadget interface {
	Call(gadget GadgetDefinition) interface{}
}

type GadgetDefinition interface {
	DefineGadget(api API) interface{}
}

type API interface {
	frontend.API
	DefineGadget(gadget GadgetDefinition) Gadget

	frontend.API
	Call(gadget GadgetDefinition) interface{}
}

type Circuit interface {
	frontend.Circuit
	AbsDefine(api API) error
}

func Concretize(api frontend.API, circuit Circuit) error {
	return circuit.AbsDefine(&Concretizer{api})
}

func CallGadget(api frontend.API, circuit GadgetDefinition) interface{} {
	_, ok := api.(API)
	if ok {
		// The consequence of calling CallGadget with abstractor.API is that
		// the circuit is extracted as a single function instead of
		// splitting in sub-circuits
		panic("abstractor.CallGadget can't be called with abstractor.API")
	}
	return circuit.DefineGadget(&Concretizer{api})
}
