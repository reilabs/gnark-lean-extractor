package abstractor

import "github.com/consensys/gnark/frontend"

type Gadget interface {
	Call(gadget interface{}) []frontend.Variable
}

type API interface {
	frontend.API
	DefineGadget(gadget interface{}, constructor func(api API, gadget interface{}) []frontend.Variable) Gadget
}

type Circuit interface {
	frontend.Circuit
	AbsDefine(api API) error
}

func Concretize(api frontend.API, circuit Circuit) error {
	return circuit.AbsDefine(&Concretizer{api})
}
