package extractor

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/abstractor"
)

func CallVoid(api abstractor.API, gadget abstractor.GadgetDefinition) {
	api.Call(gadget)
}

func Call(api abstractor.API, gadget abstractor.GadgetDefinition) frontend.Variable {
	return api.Call(gadget).(frontend.Variable)
}

func Call1(api abstractor.API, gadget abstractor.GadgetDefinition) []frontend.Variable {
	return api.Call(gadget).([]frontend.Variable)
}

func Call2(api abstractor.API, gadget abstractor.GadgetDefinition) [][]frontend.Variable {
	return api.Call(gadget).([][]frontend.Variable)
}

func Call3(api abstractor.API, gadget abstractor.GadgetDefinition) [][][]frontend.Variable {
	return api.Call(gadget).([][][]frontend.Variable)
}
