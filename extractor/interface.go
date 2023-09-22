package extractor

import (
	"fmt"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/abstractor"
	"golang.org/x/exp/slices"
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

func CircuitToLeanWithName(circuit abstractor.Circuit, field ecc.ID, namespace string) (string, error) {
	schema, err := getSchema(circuit)
	if err != nil {
		return "", err
	}

	err = circuitInit(circuit, schema)
	if err != nil {
		fmt.Println("CircuitInit error!")
		fmt.Println(err.Error())
	}

	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	err = circuit.AbsDefine(&api)
	if err != nil {
		return "", err
	}

	extractorCircuit := ExCircuit{
		Inputs:  getExArgs(circuit, schema.Fields),
		Gadgets: api.Gadgets,
		Code:    api.Code,
		Field:   api.FieldID,
	}
	out := exportCircuit(extractorCircuit, namespace)
	return out, nil
}

func CircuitToLean(circuit abstractor.Circuit, field ecc.ID) (string, error) {
	name := getStructName(circuit)
	return CircuitToLeanWithName(circuit, field, name)
}

func GadgetToLeanWithName(gadget abstractor.GadgetDefinition, field ecc.ID, namespace string) (string, error) {
	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	api.DefineGadget(gadget)
	gadgets := exportGadgets(api.Gadgets)
	prelude := exportPrelude(namespace, api.FieldID.ScalarField())
	footer := exportFooter(namespace)
	return fmt.Sprintf("%s\n\n%s\n\n%s", prelude, gadgets, footer), nil
}

func GadgetToLean(gadget abstractor.GadgetDefinition, field ecc.ID) (string, error) {
	name := getStructName(gadget)
	return GadgetToLeanWithName(gadget, field, name)
}

func ExtractCircuits(namespace string, field ecc.ID, circuits ...abstractor.Circuit) (string, error) {
	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	var circuits_extracted []string
	var past_circuits []string

	extractorCircuit := ExCircuit{
		Inputs:  []ExArg{},
		Gadgets: []ExGadget{},
		Code:    []App{},
		Field:   api.FieldID,
	}

	for _, circuit := range circuits {
		schema, err := getSchema(circuit)
		if err != nil {
			return "", err
		}
		args := getExArgs(circuit, schema.Fields)
		name := generateUniqueName(circuit, args)
		if slices.Contains(past_circuits, name) {
			continue
		}
		past_circuits = append(past_circuits, name)

		err = circuitInit(circuit, schema)
		if err != nil {
			fmt.Println("CircuitInit error!")
			fmt.Println(err.Error())
		}
		err = circuit.AbsDefine(&api)
		if err != nil {
			return "", err
		}

		extractorCircuit.Inputs = args
		extractorCircuit.Code = api.Code

		circ := fmt.Sprintf("def %s %s: Prop :=\n%s", name, genArgs(extractorCircuit.Inputs), genCircuitBody(extractorCircuit))
		circuits_extracted = append(circuits_extracted, circ)

		// Resetting elements for next circuit
		extractorCircuit.Inputs = []ExArg{}
		extractorCircuit.Code = []App{}
		api.Code = []App{}
	}

	prelude := exportPrelude(namespace, extractorCircuit.Field.ScalarField())
	gadgets := exportGadgets(api.Gadgets)
	footer := exportFooter(namespace)
	return fmt.Sprintf("%s\n\n%s\n\n%s\n\n%s", prelude, gadgets, strings.Join(circuits_extracted, "\n\n"), footer), nil
}

func ExtractGadgets(namespace string, field ecc.ID, gadgets ...abstractor.GadgetDefinition) (string, error) {
	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	for _, gadget := range gadgets {
		api.DefineGadget(gadget)
	}

	gadgets_string := exportGadgets(api.Gadgets)
	prelude := exportPrelude(namespace, api.FieldID.ScalarField())
	footer := exportFooter(namespace)
	return fmt.Sprintf("%s\n\n%s\n\n%s", prelude, gadgets_string, footer), nil
}