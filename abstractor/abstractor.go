package abstractor

import "github.com/consensys/gnark/frontend"

type Gadget interface {
	Call(gadget GadgetDefinition) interface{}
}

type GadgetDefinition interface {
	DefineGadget(api frontend.API) interface{}
}
