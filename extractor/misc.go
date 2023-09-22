package extractor

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/schema"
	"github.com/mitchellh/copystructure"
	"github.com/reilabs/gnark-lean-extractor/abstractor"
)

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

func kindOfField(a any, s string) reflect.Kind {
	v := reflect.ValueOf(a).Elem()
	f := v.FieldByName(s)
	return f.Kind()
}

func getStructName(circuit any) string {
	return reflect.TypeOf(circuit).Elem().Name()
}

func updateProj(gate Operand, extra ...int) Proj {
	if len(extra) == 2 {
		return Proj{gate, extra[0], extra[1]}
	}
	return Proj{updateProj(gate, extra[:len(extra)-2]...), extra[len(extra)-2], extra[len(extra)-1]}
}

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
		fmt.Printf("invalid argument of type %T %#v\n", gOutputs, gOutputs)
		panic("invalid argument")
	}
}

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
			fmt.Printf("-- Gadget name doesn't differentiate yet between different initialised values of type %+v.\n", val.Field(i).Kind())
			fmt.Println("-- Proceed with caution")
		}
	}
	return fmt.Sprintf("%s%s", reflect.TypeOf(element).Elem().Name(), suffix)
}

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