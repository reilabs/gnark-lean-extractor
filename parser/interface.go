package parser

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/reilabs/lean-circuit-compiler/abstractor"
	"github.com/reilabs/lean-circuit-compiler/extractor"
	"golang.org/x/exp/slices"
)

// CircuitToLeanWithName exports a `circuit` to Lean over a `field` with `namespace`
// CircuitToLeanWithName and CircuitToLean aren't joined in a single function
// CircuitToLean(circuit abstractor.Circuit, field ecc.ID, namespace ...string) because the long term view
// is to add an optional parameter to support custom `set_option` directives in the header.
func CircuitToLeanWithName(circuit extractor.ExtractorCircuit, field ecc.ID, namespace string) (out string, err error) {
	defer recoverError()

	schema, err := getSchema(circuit)
	if err != nil {
		return "", err
	}

	extractor.CircuitInit(circuit, schema)

	api := GetExtractor(field)
	err = circuit.Define(&api)
	if err != nil {
		return "", err
	}

	return extractor.GenerateLeanCode(namespace, &api.ext, circuit, schema.Fields)
}

// CircuitToLean exports a `circuit` to Lean over a `field` with the namespace being the
// struct name of `circuit`
// When the namespace argument is not defined, it uses the name of the struct circuit
func CircuitToLean(circuit extractor.ExtractorCircuit, field ecc.ID) (string, error) {
	name := getStructName(circuit)
	return CircuitToLeanWithName(circuit, field, name)
}

// GadgetToLeanWithName exports a `gadget` to Lean over a `field` with `namespace`
// Same notes written for CircuitToLeanWithName apply to GadgetToLeanWithName and GadgetToLean
func GadgetToLeanWithName(gadget abstractor.GadgetDefinition, field ecc.ID, namespace string) (out string, err error) {
	defer recoverError()

	api := GetExtractor(field)
	api.DefineGadget(gadget)
	return extractor.ExportGadgetsOnly(namespace, api.ext.GetGadgets(), api.ext.GetField()), nil
}

// GadgetToLean exports a `gadget` to Lean over a `field`
func GadgetToLean(gadget abstractor.GadgetDefinition, field ecc.ID) (string, error) {
	name := getStructName(gadget)
	return GadgetToLeanWithName(gadget, field, name)
}

// ExtractCircuits is used to export a series of `circuits` to Lean over a `field` under `namespace`.
func ExtractCircuits(namespace string, field ecc.ID, circuits ...extractor.ExtractorCircuit) (out string, err error) {
	defer recoverError()

	api := GetExtractor(field)

	var circuits_extracted []string
	var past_circuits []string

	for _, circuit := range circuits {
		schema, err := getSchema(circuit)
		if err != nil {
			return "", err
		}
		name := extractor.GenerateCircuitName(circuit, schema.Fields)
		if slices.Contains(past_circuits, name) {
			continue
		}
		past_circuits = append(past_circuits, name)

		extractor.CircuitInit(circuit, schema)
		err = circuit.Define(&api)
		if err != nil {
			return "", err
		}

		circuit_def := extractor.GenerateLeanCircuit(name, &api.ext, circuit, schema.Fields)
		circuits_extracted = append(circuits_extracted, circuit_def)

		// Resetting elements for next circuit
		api.ext.ResetCode()
	}

	return extractor.GenerateLeanCircuits(namespace, &api.ext, circuits_extracted), nil
}

// ExtractGadgets is used to export a series of `gadgets` to Lean over a `field` under `namespace`.
func ExtractGadgets(namespace string, field ecc.ID, gadgets ...abstractor.GadgetDefinition) (out string, err error) {
	defer recoverError()

	api := GetExtractor(field)

	for _, gadget := range gadgets {
		api.DefineGadget(gadget)
	}
	return extractor.ExportGadgetsOnly(namespace, api.ext.GetGadgets(), api.ext.GetField()), nil
}
