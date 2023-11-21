package parser

import (
	"errors"
	"flag"
	"fmt"
	"reflect"
	"runtime/debug"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
)

// getSchema is a cloned version of NewSchema without constraints
func getSchema(circuit any) (*schema.Schema, error) {
	tVariable := reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
	return schema.New(circuit, tVariable)
}

// getStructName returns the name of struct a
func getStructName(a any) string {
	return reflect.TypeOf(a).Elem().Name()
}

// recoverError is used in the top level interface to prevent panic
// caused by any of the methods in the extractor from propagating
// When go is running in test mode, it prints the stack trace to aid
// debugging.
func recoverError() (err error) {
	if recover() != nil {
		if flag.Lookup("test.v") != nil {
			stack := string(debug.Stack())
			fmt.Println(stack)
		}
		err = errors.New("Panic extracting circuit to Lean")
	}
	return nil
}
