// This file contains the public API for running the extractor.
package extractor

import (
	"fmt"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
)

func GetExtractor(field ecc.ID) CodeExtractor {
	return CodeExtractor{
		Code:    []App{},
		Gadgets: []ExGadget{},
		FieldID: field,
	}
}

func GenerateCircuitName(circuit ExtractorCircuit, fields []ExtractorField) string {
	args := getExArgs(circuit, fields)
	return generateUniqueName(circuit, args)
}

func GenerateLeanCode(namespace string, ext ExtractorApi, circuit ExtractorCircuit, fields []ExtractorField) (out string, err error) {
	extractorCircuit := ExCircuit{
		Inputs:  getExArgs(circuit, fields),
		Gadgets: ext.GetGadgets(),
		Code:    ext.GetCode(),
		Field:   ext.GetField(),
	}
	out = exportCircuit(extractorCircuit, namespace)
	return out, nil
}

func GenerateLeanCircuit(name string, ext ExtractorApi, circuit ExtractorCircuit, fields []ExtractorField) string {
	extractorCircuit := ExCircuit{
		Inputs:  getExArgs(circuit, fields),
		Gadgets: []ExGadget{},
		Code:    ext.GetCode(),
		Field:   ext.GetField(),
	}
	return fmt.Sprintf("def %s %s: Prop :=\n%s", name, genArgs(extractorCircuit.Inputs), genCircuitBody(extractorCircuit))
}

func GenerateLeanCircuits(namespace string, ext ExtractorApi, circuits []string) string {
	prelude := exportPrelude(namespace, ext.GetField().ScalarField())
	gadgets := exportGadgets(ext.GetGadgets())
	footer := exportFooter(namespace)
	return fmt.Sprintf("%s\n\n%s\n\n%s\n\n%s", prelude, gadgets, strings.Join(circuits, "\n\n"), footer)
}
