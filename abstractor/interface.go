// This file contains the public API for using the extractor.
// The Call functions are used to call gadgets and get their returnd object.
// These methods are prepared for doing automated casting from interface{}.
// Alternatively it's possible to do manual casting by calling
// abstractor.API.Call() and casting the result to the needed type.
package abstractor

import (
	"github.com/consensys/gnark/frontend"
)

// Call is used to call a Gadget which returns frontend.Variable (i.e. a single element `F` in Lean)
func Call(api frontend.API, gadget GadgetDefinition) frontend.Variable {
	if abs, ok := api.(API); ok {
		return abs.Call(gadget).(frontend.Variable)
	} else {
		return gadget.DefineGadget(api).(frontend.Variable)
	}
}

// CallVoid is used to call a Gadget which doesn't return anything
func CallVoid(api frontend.API, gadget GadgetDefinition) {
	Call(api, gadget)
}

// Call1 is used to call a Gadget which returns []frontend.Variable (i.e. `Vector F d` in Lean)
func Call1(api frontend.API, gadget GadgetDefinition) []frontend.Variable {
	return Call(api, gadget).([]frontend.Variable)
}

// Call2 is used to call a Gadget which returns a [][]frontend.Variable
// (i.e. `Vector (Vector F a) b` in Lean)
func Call2(api frontend.API, gadget GadgetDefinition) [][]frontend.Variable {
	return Call(api, gadget).([][]frontend.Variable)
}

// Call3 is used to call a Gadget which returns a [][][]frontend.Variable
// (i.e. `Vector (Vector (Vector F a) b) c` in Lean)
func Call3(api frontend.API, gadget GadgetDefinition) [][][]frontend.Variable {
	return Call(api, gadget).([][][]frontend.Variable)
}
