package vergo

import (
	"fmt"
	"runtime"
	"strings"
)

func getQualifiedCallerName(skip int) string {
	pc, _, _, ok := runtime.Caller(skip + 1)
	if !ok {
		panic("oops")
	}
	frames := runtime.CallersFrames((&[1]uintptr{pc})[:])
	frame, _ := frames.Next()
	return frame.Function
}

type Op struct {
	tag     string
	inputs  []Variable
	outputs []Variable
}

func (o Op) StringWithIndent(indent int) string {
	indents := strings.Repeat("\t", indent)
	results := make([]string, len(o.outputs))
	for i, v := range o.outputs {
		results[i] = fmt.Sprintf("v%d", v.id)
	}
	inputs := make([]string, len(o.inputs))
	for i, v := range o.inputs {
		inputs[i] = fmt.Sprintf("v%d", v.id)
	}
	res := fmt.Sprintf("%s%s := %s(%s)", indents, strings.Join(results, ", "), o.tag, strings.Join(inputs, ", "))
	return res
}

type Scope struct {
	lastVar int
	ops     []Op
}

func (s *Scope) String() string {
	res := ""
	for _, op := range s.ops {
		res += op.StringWithIndent(1) + "\n"
	}
	return res
}

func (s *Scope) NewVariable() Variable {
	s.lastVar++
	return Variable{
		id:    s.lastVar,
		scope: s,
	}
}

var globalScope *Scope = nil

func NewScope() *Scope {
	return &Scope{}
}

type Variable struct {
	id    int
	scope *Scope
}

type Vergo[T any] struct {
	Variable *Variable
	Value    T
}

func (vergo *Vergo[T]) OfVar(v *Variable) *Vergo[T] {
	vergo.Variable = v
	return vergo
}

func IsExtracting() bool {
	return globalScope != nil
}

func PrimOp1[T any](handler func() T, vars ...Variable) Vergo[T] {
	if globalScope == nil {
		return Vergo[T]{Value: handler()}
	} else {
		res := globalScope.NewVariable()
		globalScope.ops = append(globalScope.ops, Op{getQualifiedCallerName(1), vars, []Variable{res}})
		return Vergo[T]{Variable: &res}
	}
}

func StartExtracting() {
	globalScope = NewScope()
}

func StopExtracting() *Scope {
	res := globalScope
	globalScope = nil
	return res
}

func FreeVar() *Variable {
	if globalScope == nil {
		return nil
	}
	r := globalScope.NewVariable()
	return &r
}
