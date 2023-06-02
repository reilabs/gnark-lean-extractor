package extractor

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"gnark-extractor/abstractor"
	"testing"
)

func defineExample(api abstractor.API) {
	my_widget := api.DefineGadget("my_widget", 2, func(api abstractor.API, args ...frontend.Variable) []frontend.Variable {
		sum := api.Add(args[0], args[1])
		mul := api.Mul(args[0], args[1])
		r := api.Div(sum, mul)
		return []frontend.Variable{r}
	})
	my_snd_widget := api.DefineGadget("my_snd_widget", 2, func(api abstractor.API, args ...frontend.Variable) []frontend.Variable {
		mul := api.Mul(args[0], args[1])
		snd := my_widget.Call(args[0], args[1])
		r := api.Mul(mul, snd[0])
		return []frontend.Variable{r}
	})
	i1 := Input{0}
	i2 := Input{1}
	sum := api.Add(i1, i2)
	prod := api.Mul(i1, i2)
	my_snd_widget.Call(sum, prod)
}

func TestExtractor(t *testing.T) {
	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
	}
	defineExample(&api)
	circuit := ExCircuit{
		Inputs:  []string{"i1", "i2"},
		Gadgets: api.Gadgets,
		Code:    api.Code,
	}
	fmt.Println(ExportCircuit(circuit))
}
