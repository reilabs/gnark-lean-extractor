package extractor

import (
	"errors"
	"flag"
	"fmt"
	"reflect"
	"runtime/debug"
	"strings"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/mitchellh/copystructure"
	"github.com/reilabs/gnark-lean-extractor/v2/abstractor"
)

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

// arrayToSlice returns a slice of elements identical to
// the input array `v`
func arrayToSlice(v reflect.Value) []frontend.Variable {
	if v.Len() == 0 {
		return []frontend.Variable{}
	}

	switch v.Index(0).Kind() {
	case reflect.Array:
		args := []frontend.Variable{}
		for i := 0; i < v.Len(); i++ {
			arg := arrayToSlice(v.Index(i))
			// The reason to check for len != 0 is to avoid generating
			// lists of empty nested lists
			if len(arg) != 0 {
				args = append(args, arg)
			}
		}
		return args
	case reflect.Interface:
		res := []frontend.Variable{}
		for i := 0; i < v.Len(); i++ {
			res = append(res, v.Index(i).Elem().Interface().(frontend.Variable))
		}
		return res
	default:
		return []frontend.Variable{}
	}
}

// flattenSlice takes a slice and returns a single dimension
// slice of frontend.Variable. This is needed to transform
// nested slices into single dimensional slices to be
// processed by sanitizeVars.
func flattenSlice(value reflect.Value) []frontend.Variable {
	if value.Len() == 0 {
		return []frontend.Variable{}
	}
	if value.Index(0).Kind() == reflect.Slice {
		args := []frontend.Variable{}
		for i := 0; i < value.Len(); i++ {
			arg := flattenSlice(value.Index(i))
			// The reason to check for len != 0 is to avoid generating
			// lists of empty nested lists
			if len(arg) != 0 {
				args = append(args, arg)
			}
		}
		return args
	}
	return value.Interface().([]frontend.Variable)
}

// arrayInit generates the Proj{} object for each element of v
func arrayInit(f schema.Field, v reflect.Value, op Operand) error {
	for i := 0; i < f.ArraySize; i++ {
		op := Proj{op, i, f.ArraySize}
		switch len(f.SubFields) {
		case 1:
			arrayInit(f.SubFields[0], v.Index(i), op)
		case 0:
			if v.Len() != f.ArraySize {
				// Slices of this type aren't supported yet [[<nil> <nil> <nil>] [<nil> <nil>]]
				// gnark newSchema doesn't handle different dimensions
				fmt.Printf("Wrong slices dimensions %+v\n", v)
				panic("Only slices dimensions not matching")
			}
			value := reflect.ValueOf(op)
			v.Index(i).Set(value)
		default:
			panic("Only nested arrays supported in SubFields")
		}
	}
	return nil
}

// arrayZero sets all the elements of the input slice v to nil.
// It is used when initialising a new circuit or gadget to ensure
// the object is clean
func arrayZero(v reflect.Value) {
	switch v.Kind() {
	case reflect.Slice:
		if v.Len() != 0 {
			// Check if there are nested arrays. If yes, continue recursion
			// until most nested array
			if v.Addr().Elem().Index(0).Kind() == reflect.Slice {
				for i := 0; i < v.Len(); i++ {
					arrayZero(v.Addr().Elem().Index(i))
				}
			} else {
				zero_array := make([]frontend.Variable, v.Len(), v.Len())
				v.Set(reflect.ValueOf(&zero_array).Elem())
			}
		}
	default:
		panic("Only nested slices supported in SubFields of slices")
	}
}

// kindOfField returns the Kind of field in struct a
func kindOfField(a any, field string) reflect.Kind {
	v := reflect.ValueOf(a).Elem()
	f := v.FieldByName(field)
	return f.Kind()
}

// getStructName returns the name of struct a
func getStructName(a any) string {
	return reflect.TypeOf(a).Elem().Name()
}

// updateProj recursively creates a Proj object using the `Index` and `Size` from the
// optional argument `extra`. It uses the argument `gate` as Operand for the innermost Proj.
// The `extra` optional argument contains the `Index` in even indices and the `Size` in odd indices,
// elements are discarded from the end.
func updateProj(gate Operand, extra ...int) Proj {
	if len(extra) == 2 {
		return Proj{gate, extra[0], extra[1]}
	} else if len(extra) > 0 && len(extra)%2 == 0 {
		return Proj{updateProj(gate, extra[:len(extra)-2]...), extra[len(extra)-2], extra[len(extra)-1]}
	}
	fmt.Printf("updateProj gate: %#v | extra: %+v", gate, extra)
	panic("updateProj called with wrong number of elements in extra")
}

// replaceArg generates the object returned when calling the gadget in a circuit.
// The object returned has the same structure as ExGadget.OutputsFlat but it needs
// to have updated `Proj` fields. gate argument corresponds to the `Gate` object of the
// gadget call. extra argument keeps track of the `Size` and `Index` elements of the nested
// Proj. These need to be replaced because the output of a gadget is a combination
// of Proj.
func replaceArg(gOutputs interface{}, gate Operand, extra ...int) interface{} {
	// extra[0] -> i
	// extra[1] -> len
	switch v := (gOutputs).(type) {
	case Input, Gate:
		if len(extra) == 2 {
			return Proj{gate, extra[0], extra[1]}
		}
		return gate
	case Proj:
		if len(extra) >= 2 {
			return updateProj(gate, extra...)
		}
		return gate
	case []frontend.Variable:
		res := make([]frontend.Variable, len(v))
		for i, o := range v {
			res[i] = replaceArg(o, gate, append(extra, []int{i, len(v)}...)...)
		}
		return res
	case [][]frontend.Variable:
		res := make([][]frontend.Variable, len(v))
		for i, o := range v {
			res[i] = replaceArg(o, gate, append(extra, []int{i, len(v)}...)...).([]frontend.Variable)
		}
		return res
	case [][][]frontend.Variable:
		res := make([][][]frontend.Variable, len(v))
		for i, o := range v {
			res[i] = replaceArg(o, gate, append(extra, []int{i, len(v)}...)...).([][]frontend.Variable)
		}
		return res
	case nil:
		return []frontend.Variable{}
	default:
		fmt.Printf("replaceArg invalid argument of type %T %#v\n", gOutputs, gOutputs)
		panic("replaceArg invalid argument")
	}
}

// cloneGadget performs deep cloning of `gadget`
func cloneGadget(gadget abstractor.GadgetDefinition) abstractor.GadgetDefinition {
	dup, err := copystructure.Copy(gadget)
	if err != nil {
		panic(err)
	}
	// The reason for the following lines is to generate a reflect.Ptr to the interface
	v := reflect.ValueOf(dup)
	tmp_gadget := reflect.New(v.Type())
	tmp_gadget.Elem().Set(v)
	return tmp_gadget.Interface().(abstractor.GadgetDefinition)
}

// generateUniqueName is a function that generates the gadget function name in Lean
// To distinguish between gadgets instantiated with different array
// sizes, add a suffix to the name. The suffix of each instantiation
// is made up of the concatenation of the length of all the array
// fields in the gadget
func generateUniqueName(element any, args []ExArg) string {
	suffix := ""
	for _, a := range args {
		if a.Kind == reflect.Array || a.Kind == reflect.Slice {
			suffix += "_"
			suffix += strings.Join(getSizeGadgetArgs(a.Type), "_")
		}
	}

	val := reflect.ValueOf(element).Elem()
	for i := 0; i < val.NumField(); i++ {
		switch val.Field(i).Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			suffix += fmt.Sprintf("_%d", val.Field(i).Int())
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			suffix += fmt.Sprintf("_%d", val.Field(i).Uint())
		case reflect.Uintptr, reflect.Float32, reflect.Float64, reflect.Complex64, reflect.Complex128:
			fmt.Printf("-- Gadget name doesn't differentiate yet between different values of type %+v.\n", val.Field(i).Kind())
			fmt.Println("-- Proceed with caution")
		}
	}
	return fmt.Sprintf("%s%s", reflect.TypeOf(element).Elem().Name(), suffix)
}

// getGadgetByName checks if `name` matches the ExGadget.Name of one of
// the elements in `gadgets`
func getGadgetByName(gadgets []ExGadget, name string) abstractor.Gadget {
	for _, gadget := range gadgets {
		if gadget.Name == name {
			return &gadget
		}
	}
	return nil
}

// getSizeGadgetArgs generates the concatenation of dimensions of
// a slice/array (i.e. [3][2]frontend.Variable --> ["3","2"])
// It is used to generate a unique gadget name
func getSizeGadgetArgs(elem ExArgType) []string {
	if elem.Type == nil {
		return []string{fmt.Sprintf("%d", elem.Size)}
	}
	return append(getSizeGadgetArgs(*elem.Type), fmt.Sprintf("%d", elem.Size))
}
