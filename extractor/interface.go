// This file contains the public API for running the extractor.
package extractor

import (
	"fmt"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"golang.org/x/exp/slices"
)

// CircuitToLeanWithName exports a `circuit` to Lean over a `field` with `namespace`
// CircuitToLeanWithName and CircuitToLean aren't joined in a single function
// CircuitToLean(circuit abstractor.Circuit, field ecc.ID, namespace ...string) because the long term view
// is to add an optional parameter to support custom `set_option` directives in the header.
func CircuitToLeanWithName(circuit frontend.Circuit, field ecc.ID, namespace string) (out string, err error) {
	defer recoverError()

	schema, err := getSchema(circuit)
	if err != nil {
		return "", err
	}

	circuitInit(circuit, schema)

	api := CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}

	err = circuit.Define(&api)
	if err != nil {
		return "", err
	}

	extractorCircuit := ExCircuit{
		Inputs:  getExArgs(circuit, schema.Fields),
		Gadgets: api.Gadgets,
		Code:    api.Code,
		Field:   api.FieldID,
	}
	out = exportCircuit(extractorCircuit, namespace)
	return out, nil
}

// CircuitToLean exports a `circuit` to Lean over a `field` with the namespace being the
// struct name of `circuit`
// When the namespace argument is not defined, it uses the name of the struct circuit
func CircuitToLean(circuit frontend.Circuit, field ecc.ID) (string, error) {
	name := getStructName(circuit)
	return CircuitToLeanWithName(circuit, field, name)
}

// GadgetToLeanWithName exports a `gadget` to Lean over a `field` with `namespace`
// Same notes written for CircuitToLeanWithName apply to GadgetToLeanWithName and GadgetToLean
func GadgetToLeanWithName(gadget abstractor.GadgetDefinition, field ecc.ID, namespace string) (out string, err error) {
	defer recoverError()

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

// GadgetToLean exports a `gadget` to Lean over a `field`
func GadgetToLean(gadget abstractor.GadgetDefinition, field ecc.ID) (string, error) {
	name := getStructName(gadget)
	return GadgetToLeanWithName(gadget, field, name)
}

// ExtractCircuits is used to export a series of `circuits` to Lean over a `field` under `namespace`.
func ExtractCircuits(namespace string, field ecc.ID, circuits ...frontend.Circuit) (out string, err error) {
	defer recoverError()

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

		circuitInit(circuit, schema)
		err = circuit.Define(&api)
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

// ExtractGadgets is used to export a series of `gadgets` to Lean over a `field` under `namespace`.
func ExtractGadgets(namespace string, field ecc.ID, gadgets ...abstractor.GadgetDefinition) (out string, err error) {
	defer recoverError()

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
