package extractor_test

import (
	"fmt"
	"github.com/google/uuid"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/consensys/gnark/frontend"
)

type Statement interface {
	StringInd(indent int) string
}

type Call struct {
	fn     string
	id     uuid.UUID
	gadget *GadgetDef
}

func (c Call) StringInd(indent int) string {
	return fmt.Sprintf("%s%s@%s()", strings.Repeat("\t", indent), c.fn, c.id.String()[:8])
}

type PrimOp struct {
	tag     string
	args    []Variable
	results []Variable
}

func (po PrimOp) StringInd(indent int) string {
	results := make([]string, len(po.results))
	for i, r := range po.results {
		results[i] = r.id.String()[:8]
	}
	args := make([]string, len(po.args))
	for i, a := range po.args {
		args[i] = a.id.String()[:8]
	}
	return fmt.Sprintf("%s%s := %s(%s)", strings.Repeat("\t", indent), strings.Join(results, ", "), po.tag, strings.Join(args, ", "))
}

type Loop struct {
	bound   Variable
	counter Variable
	body    []Statement
}

func (l Loop) StringInd(indent int) string {
	res := fmt.Sprintf("%sfor %s := 0; %s < %s; %s++ {\n", strings.Repeat("\t", indent), l.counter.id.String()[:8], l.counter.id.String()[:8], l.bound.id.String()[:8], l.counter.id.String()[:8])
	for _, s := range l.body {
		res += s.StringInd(indent+1) + "\n"
	}
	res += strings.Repeat("\t", indent) + "}"
	return res
}

type ParentType int

const (
	Caller ParentType = iota
	Lexical
)

type GadgetDef struct {
	parent        *GadgetDef
	parentType    ParentType
	localVarCount int
	statements    []Statement
	arguments     []Variable
}

//func (g *GadgetDef) String() string {
//
//}

func newGadget() *GadgetDef {
	return &GadgetDef{}
}

func (g *GadgetDef) newChild() *GadgetDef {
	return &GadgetDef{parent: g}
}

func (g *GadgetDef) addCall(fn string, id uuid.UUID, gadget *GadgetDef) {
	g.statements = append(g.statements, Call{fn, id, gadget})
}

func (g *GadgetDef) addOp1(name string, args ...Variable) Variable {
	r := Variable{
		id:    uuid.New(),
		scope: g,
	}
	g.statements = append(g.statements, PrimOp{
		tag:     name,
		args:    args,
		results: (&[1]Variable{r})[:],
	})
	return r
}

type StackFrame struct {
	fn     string
	callId uuid.UUID
}

type ExtractionEnv struct {
	functionCalls map[string]map[uuid.UUID]*GadgetDef
	currentGadget *GadgetDef
}

func (env *ExtractionEnv) Enter(fn string) {
	id := uuid.New()
	if env.functionCalls[fn] == nil {
		env.functionCalls[fn] = make(map[uuid.UUID]*GadgetDef)
	}

	gadget := env.currentGadget.newChild()
	env.currentGadget.addCall(fn, id, gadget)
	env.functionCalls[fn][id] = gadget
	env.currentGadget = gadget
}

func (env *ExtractionEnv) Leave() {
	env.currentGadget = env.currentGadget.parent
}

func (env *ExtractionEnv) EnterLexical() {
	env.currentGadget = env.currentGadget.newChild()
}

func (env *ExtractionEnv) LeaveLexical() *GadgetDef {
	res := env.currentGadget
	env.currentGadget = env.currentGadget.parent
	return res
}

var env *ExtractionEnv = nil

func NewTopEnv() *ExtractionEnv {
	return &ExtractionEnv{functionCalls: make(map[string]map[uuid.UUID]*GadgetDef), currentGadget: newGadget()}
}

func IsExtracting() bool {
	return env != nil
}

//if IsExtracting() {
//var r Traceable
//switch v := any(*Value).(type) {
//case Variable:
//r = &v
//}
//println(r)
////_, ok := any(*Value).(Traceable)
////if !ok {
////	panic(fmt.Sprintf("non-traceable value used during program extraction: %v %v", *Value, reflect.TypeOf(Value)))
////}
//res.Variable = env.currentGadget.addOp1("NewMutable", r.GetVariable())
//
//}

func getVariable(v interface{}) Variable {
	switch v := v.(type) {
	case Variable:
		return v
	case *Variable:
		return *v
	case Int:
		return v.Variable
	case *Int:
		return v.Variable
	case Slice[any]:
		return v.Variable
	case *Slice[any]:
		return v.Variable

	default:
		panic("unexpected type")
	}
}

func AddOp1(tag string, args ...interface{}) Variable {
	if IsExtracting() {
		variables := make([]Variable, len(args))
		for i, arg := range args {
			variables[i] = getVariable(arg)
		}
		return env.currentGadget.addOp1(tag, variables...)
	}
	return Variable{}
}

func AddLoop(r Int, callback func(Int)) {
	if IsExtracting() {
		counter := NewVariable("i")
		env.EnterLexical()
		callback(Int{Variable: counter})
		body := env.LeaveLexical()
		loop := Loop{
			bound:   getVariable(r),
			counter: counter,
			body:    body.statements,
		}
		env.currentGadget.statements = append(env.currentGadget.statements, loop)
	}
}

type API2 interface {
	Mul(frontend.Variable, frontend.Variable) frontend.Variable
	Select(frontend.Variable, frontend.Variable, frontend.Variable) frontend.Variable
}

type APISentinel struct {
}

func NewAPISentinel() *APISentinel {
	return &APISentinel{}
}

func (api *APISentinel) Mul(a, b frontend.Variable) frontend.Variable {
	return AddOp1("api.Mul", a, b)
}

func (api *APISentinel) Select(a, b, c frontend.Variable) frontend.Variable {
	return AddOp1("api.Select", a, b, c)
}

type Variable struct {
	id    uuid.UUID
	scope *GadgetDef
}

func Into[T any](v Variable) T {
	var result T
	fmt.Printf("type: %v\n", reflect.TypeOf(any(result)))
	switch any(result).(type) {
	case Int:
		return any(Int{Variable: v}).(T)
	case *Int:
		return any(&Int{Variable: v}).(T)
	case frontend.Variable:
		return any(v).(T)
	case nil:
		return any(v).(T)
	}
	return result
}

type Traceable interface {
	GetVariable() Variable
}

func (v Variable) GetVariable() Variable {
	return v
}

//type Value[T any] struct {
//	Variable Variable
//	Value    T
//}
//
//func (i Value[int]) Add(j Value[int]) Value[int] {
//	return Value[int]{Value: i.Value + j.Value}
//}

func NewVariable(name string) Variable {
	var gadget *GadgetDef
	if env != nil {
		gadget = env.currentGadget
	}
	return Variable{
		id:    uuid.New(),
		scope: gadget,
	}
}

type Int struct {
	Variable Variable
	Value    int
}

func (i *Int) GetVariable() *Variable {
	return &i.Variable
}

func (i *Int) ForeachUpto(callback func(Int)) {
	AddLoop(*i, callback)
}

type Slice[T any] struct {
	Variable Variable
	Items    []T
}

func (s *Slice[T]) GetVariable() *Variable {
	return &s.Variable
}

func NewSlice[T any]() Slice[T] {
	return Slice[T]{Items: nil, Variable: NewVariable("Slice")}
}

func (s *Slice[T]) Len() *Int {
	res := &Int{Value: len(s.Items)}
	res.Variable = AddOp1("SliceLen", s.Variable)
	return res
}

func (s *Slice[T]) Get(index Int) T {
	if IsExtracting() {
		v := AddOp1("GetSlice", s.Variable, index.Variable)
		return Into[T](v)
	}
	return s.Items[index.Value]
}

type Mutable[T any] struct {
	Variable Variable
	Value    *T
}

func NewMutable[T any](Value *T) Mutable[T] {
	res := Mutable[T]{Value: Value}
	res.Variable = AddOp1("NewMutable", *Value)
	return res
}

func (mutable *Mutable[T]) Get() T {
	if IsExtracting() {
		v := AddOp1("GetMutable", mutable.Variable)
		return Into[T](v)
	} else {
		return *mutable.Value
	}
}

func (mutable *Mutable[T]) Set(newValue T) {
	mutable.Value = &newValue
}

func getQualifiedCallerName(skip int) string {
	pc, _, _, ok := runtime.Caller(skip + 1)
	if !ok {
		panic("oops")
	}
	frames := runtime.CallersFrames((&[1]uintptr{pc})[:])
	frame, _ := frames.Next()
	return frame.Function
}

func Section() {
	if IsExtracting() {
		fnName := getQualifiedCallerName(1)
		fmt.Printf("entering: %s\n", fnName)
		env.Enter(fnName)
	}
}

func EndSection() {
	if IsExtracting() {
		env.Leave()
	}
}

type Var[T any] struct {
	Variable Variable
	Value    T
}

type MyUInt Var[uint]

type MySlice[T any] Var[[]T]

func Map[T, U any](s MySlice[T], f func(Var[T]) Var[U]) MySlice[U] {
	//res := NewSlice[U]()
	//s.Len().ForeachUpto(func(i Int) {
	//	res.Items = append(res.Items, f(s.Get(i)))
	//})
	//return res
	return MySlice[U]{}
}

func (i Var[T]) test() {

}

func (i MyUInt) Add(j MyUInt) MyUInt {
	return MyUInt{Value: i.Value + j.Value}
}

//func (s MySlice[T]) Len() MyUInt {
//	return len(s.Value)
//}

func dummyHash(api API2, In1, In2 frontend.Variable) frontend.Variable {
	//Section()
	//defer EndSection()
	return api.Mul(In1, api.Mul(In1, In2))
}

func merkleRecover(api API2, Element frontend.Variable, Path, Proof Slice[frontend.Variable]) frontend.Variable {
	Section()
	defer EndSection()
	current := NewMutable(&Element)
	Path.Len().ForeachUpto(func(i Int) {
		leftHash := dummyHash(api, current.Get(), Proof.Get(i))
		rightHash := dummyHash(api, Proof.Get(i), current.Get())
		current.Set(api.Select(Path.Get(i), rightHash, leftHash))
	})
	return current.Get()
}

func TestThisThing(t *testing.T) {
	fmt.Println("TESTANDO")
	element := NewVariable("Element")
	Path := NewSlice[frontend.Variable]()
	Proof := NewSlice[frontend.Variable]()
	api := NewAPISentinel()
	env = NewTopEnv()
	merkleRecover(api, element, Path, Proof)
	fmt.Printf("PRINTING ENV:\n")
	for fn, v := range env.functionCalls {
		fmt.Printf("\t* CALLS TO: %s\n", fn)
		for call, gadget := range v {
			fmt.Printf("\t\t* CALL %s\n", call.String())
			fmt.Printf("\t\t\tBODY:\n")
			for _, s := range gadget.statements {
				fmt.Printf("%s\n", s.StringInd(4))
			}
			//fmt.Printf("\t\t\t%v", gadget)
		}
	}
	fmt.Printf("env: %v", env)
}
