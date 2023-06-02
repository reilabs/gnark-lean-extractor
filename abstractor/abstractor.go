package abstractor

import "github.com/consensys/gnark/frontend"

type Gadget interface {
	Call(args ...frontend.Variable) []frontend.Variable
}

type API interface {
	frontend.API
	DefineGadget(name string, arity int, constructor func(api API, args ...frontend.Variable) []frontend.Variable) Gadget
}

type Circuit interface {
	frontend.Circuit
	AbsDefine(api API) error
}

func Concretize(api frontend.API, circuit Circuit) error {
	return circuit.AbsDefine(&Concretizer{api})
}
