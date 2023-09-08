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

	frontend.API
	Call(gadget GadgetDefinition) []frontend.Variable
}

type Circuit interface {
	frontend.Circuit
	AbsDefine(api API) error
}

func Concretize(api frontend.API, circuit Circuit) error {
	return circuit.AbsDefine(&Concretizer{api})
}

func CallGadget(api frontend.API, circuit GadgetDefinition) []frontend.Variable {
    _, ok := api.(API)
    if ok {
    	// The consequence of calling CallGadget with abstractor.API is that
    	// the circuit is extracted as a single function instead of
    	// splitting in sub-circuits
        panic("abstractor.CallGadget can't be called with abstractor.API")
    }
	return circuit.DefineGadget(&Concretizer{api})
}
