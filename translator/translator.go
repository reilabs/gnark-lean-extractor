// Package translator statically translates gnark circuits from Go source
// into Lean 4 definitions.
//
// Unlike the extractor package (which runs a circuit against a fake
// frontend.API and records a flat trace), the translator reads the typed Go
// AST of the circuit's Define method and emits Lean code in a continuation
// monad `Circuit α := (α → Prop) → Prop`. Go functions become Lean
// definitions, Go for-loops become Lean do-notation `for` loops, and slice
// lengths stay symbolic, so the output is generic in the input sizes.
//
// Calls into packages outside the circuit's own package must be declared as
// blackboxes: they are emitted as axiomatized opaque predicates rather than
// translated.
package translator

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"golang.org/x/tools/go/packages"
)

type Config struct {
	// Dir is the directory of the Go package containing the circuit.
	Dir string
	// Circuit is the name of the struct whose Define method is translated.
	Circuit string
	// Namespace for the generated Lean code; defaults to Circuit.
	Namespace string
	// Field is the curve whose scalar field the circuit is defined over.
	Field ecc.ID
	// Blackboxes maps fully-qualified Go function names ("pkg/path.Func")
	// to Lean names. A blackboxed function is not translated: it is emitted
	// as an axiom `<Name>_pred : ... → Prop` relating inputs to outputs,
	// wrapped in a monadic definition.
	Blackboxes map[string]string
}

type translateError struct {
	pos token.Position
	msg string
}

func (e translateError) Error() string {
	if e.pos.IsValid() {
		return fmt.Sprintf("%s: %s", e.pos, e.msg)
	}
	return e.msg
}

type translator struct {
	cfg Config
	pkg *packages.Package

	defs      []string
	axioms    []string
	axiomSeen map[string]bool
	funcNames map[*types.Func]string
	inFlight  map[*types.Func]bool
	usedNames map[string]bool
	// dirtyParams records, per translated function, the signature indices of
	// slice parameters whose backing array the function (transitively)
	// writes. Go callers observe such writes through aliasing; the
	// functional translation does not, so call sites are restricted.
	dirtyParams map[*types.Func]map[int]bool
	// aliasReturns records, per translated function, the signature indices
	// of parameters whose backing array the result may alias (e.g. a
	// function that returns its own parameter). Binding such a result to a
	// different variable would create a second name for the same backing.
	aliasReturns map[*types.Func]map[int]bool
}

// Translate loads the Go package in cfg.Dir and translates the Define method
// of cfg.Circuit (plus every package-local function it transitively calls)
// into a self-contained Lean 4 file.
func Translate(cfg Config) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			if te, ok := r.(translateError); ok {
				err = te
				return
			}
			panic(r)
		}
	}()

	if cfg.Namespace == "" {
		cfg.Namespace = cfg.Circuit
	}

	mode := packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
		packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps
	pkgs, err := packages.Load(&packages.Config{Mode: mode, Dir: cfg.Dir}, ".")
	if err != nil {
		return "", err
	}
	if len(pkgs) != 1 {
		return "", fmt.Errorf("expected one package in %s, found %d", cfg.Dir, len(pkgs))
	}
	pkg := pkgs[0]
	if len(pkg.Errors) > 0 {
		return "", fmt.Errorf("package %s does not compile: %v", pkg.PkgPath, pkg.Errors[0])
	}

	t := &translator{
		cfg:          cfg,
		pkg:          pkg,
		axiomSeen:    map[string]bool{},
		funcNames:    map[*types.Func]string{},
		inFlight:     map[*types.Func]bool{},
		usedNames:    map[string]bool{},
		dirtyParams:  map[*types.Func]map[int]bool{},
		aliasReturns: map[*types.Func]map[int]bool{},
	}
	for _, r := range []string{
		"circuit", "Gates", "F", "Order", "Circuit", "Int64", "goRange",
	} {
		t.usedNames[r] = true
	}

	circuitDef := t.translateDefine()

	var b strings.Builder
	b.WriteString(t.prelude())
	for _, a := range t.axioms {
		b.WriteString("\n\n")
		b.WriteString(a)
	}
	for _, d := range t.defs {
		b.WriteString("\n\n")
		b.WriteString(d)
	}
	b.WriteString("\n\n")
	b.WriteString(circuitDef)
	b.WriteString(fmt.Sprintf("\n\nend %s\n", cfg.Namespace))
	return b.String(), nil
}

func (t *translator) errf(pos token.Pos, format string, args ...any) {
	panic(translateError{t.pkg.Fset.Position(pos), fmt.Sprintf(format, args...)})
}

// kind is the translator's type universe: Go integers (modelled bit-exactly
// as Int64 on the Lean side) and (nested lists of) field elements.
type kind struct {
	goInt bool
	depth int // 0 = F, 1 = List F, 2 = List (List F), ...
}

func (k kind) leanType() string {
	if k.goInt {
		return "Int64"
	}
	s := "F"
	for i := 0; i < k.depth; i++ {
		if s == "F" {
			s = "List F"
		} else {
			s = "List (" + s + ")"
		}
	}
	return s
}

// leanTypeParen renders the type parenthesized when needed as an argument of
// `Circuit`.
func (k kind) leanTypeParen() string {
	s := k.leanType()
	if strings.Contains(s, " ") {
		return "(" + s + ")"
	}
	return s
}

func (k kind) elem() kind { return kind{depth: k.depth - 1} }

func gnarkNamed(typ types.Type, name string) bool {
	named, ok := typ.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj.Name() == name && obj.Pkg() != nil &&
		obj.Pkg().Path() == "github.com/consensys/gnark/frontend"
}

func isVariable(typ types.Type) bool { return gnarkNamed(typ, "Variable") }
func isAPI(typ types.Type) bool      { return gnarkNamed(typ, "API") }

func (t *translator) classify(typ types.Type, pos token.Pos) kind {
	if isVariable(typ) {
		return kind{}
	}
	switch u := typ.Underlying().(type) {
	case *types.Basic:
		if u.Info()&types.IsInteger != 0 {
			return kind{goInt: true}
		}
	case *types.Slice:
		e := t.classify(u.Elem(), pos)
		if !e.goInt {
			return kind{depth: e.depth + 1}
		}
	case *types.Array:
		e := t.classify(u.Elem(), pos)
		if !e.goInt {
			return kind{depth: e.depth + 1}
		}
	}
	t.errf(pos, "unsupported type %s (expected frontend.Variable, integers, or slices/arrays of Variable)", typ)
	return kind{}
}

var leanReserved = map[string]bool{
	"let": true, "fun": true, "do": true, "if": true, "then": true,
	"else": true, "for": true, "in": true, "mut": true, "return": true,
	"pure": true, "match": true, "with": true, "end": true, "def": true,
	"axiom": true, "namespace": true, "open": true, "k": true, "out": true,
	"F": true, "Order": true, "Gates": true, "Circuit": true, "circuit": true,
}

func sanitize(name string) string {
	if leanReserved[name] {
		return name + "_"
	}
	return name
}

// uniqueName reserves a top-level Lean definition name.
func (t *translator) uniqueName(base string) string {
	name := sanitize(base)
	for i := 1; t.usedNames[name]; i++ {
		name = fmt.Sprintf("%s_%d", sanitize(base), i)
	}
	t.usedNames[name] = true
	return name
}

// findDefine locates the AST of `func (c *Circuit) Define(api frontend.API) error`.
func (t *translator) findDefine() *ast.FuncDecl {
	for _, file := range t.pkg.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv == nil || fd.Name.Name != "Define" {
				continue
			}
			recvT := fd.Recv.List[0].Type
			if se, ok := recvT.(*ast.StarExpr); ok {
				recvT = se.X
			}
			if id, ok := recvT.(*ast.Ident); ok && id.Name == t.cfg.Circuit {
				return fd
			}
		}
	}
	panic(translateError{msg: fmt.Sprintf("no Define method found for struct %s in %s", t.cfg.Circuit, t.cfg.Dir)})
}

func (t *translator) findFuncDecl(fn *types.Func) *ast.FuncDecl {
	for _, file := range t.pkg.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && fd.Recv == nil && t.pkg.TypesInfo.Defs[fd.Name] == fn {
				return fd
			}
		}
	}
	return nil
}

func (t *translator) calleeOf(call *ast.CallExpr) *types.Func {
	switch fun := unparen(call.Fun).(type) {
	case *ast.Ident:
		fn, _ := t.pkg.TypesInfo.Uses[fun].(*types.Func)
		return fn
	case *ast.SelectorExpr:
		fn, _ := t.pkg.TypesInfo.Uses[fun.Sel].(*types.Func)
		return fn
	}
	return nil
}

// resultAliases returns the named variables a call's result may alias
// (per the callee's aliasReturns summary, recursing through nested calls),
// and whether it may alias something unnamed (a field or slice element).
func (t *translator) resultAliases(call *ast.CallExpr) (map[types.Object]bool, bool) {
	objs := map[types.Object]bool{}
	external := false
	for q := range t.aliasReturns[t.calleeOf(call)] {
		if q >= len(call.Args) {
			continue
		}
		switch arg := unparen(call.Args[q]).(type) {
		case *ast.Ident:
			if obj := t.pkg.TypesInfo.Uses[arg]; obj != nil {
				objs[obj] = true
			}
		case *ast.CallExpr:
			o2, e2 := t.resultAliases(arg)
			for o := range o2 {
				objs[o] = true
			}
			external = external || e2
		case *ast.CompositeLit:
			// Fresh backing with no other name; aliasing it is harmless.
		default:
			external = true
		}
	}
	return objs, external
}

// analyzeEffects enforces the invariant the translation's value semantics
// rely on: every slice backing array has at most one live name. It computes
// two summaries per function — which slice parameters have their backing
// written (dirtyParams) and which the result may alias (aliasReturns) — and
// rejects call sites that would let Go's aliasing become observable. A
// written-position argument must be a fresh value or the rebinding form
// `x = f(..., x)` (the write lands on a backing whose only name is
// immediately rebound to the equal-by-induction result); a result that may
// alias an argument may only be bound back to that same variable.
func (t *translator) analyzeEffects(fn *types.Func, body *ast.BlockStmt, paramObjs []types.Object) {
	info := t.pkg.TypesInfo
	paramIdx := map[types.Object]int{}
	for i, o := range paramObjs {
		if o != nil {
			paramIdx[o] = i
		}
	}

	dirty := map[int]bool{}
	markIdent := func(e ast.Expr) {
		if id, ok := unparen(e).(*ast.Ident); ok {
			if i, ok := paramIdx[info.Uses[id]]; ok {
				dirty[i] = true
			}
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok != token.DEFINE {
				for _, l := range n.Lhs {
					if ix, ok := l.(*ast.IndexExpr); ok {
						markIdent(ix.X)
					}
				}
			}
		case *ast.CallExpr:
			for p := range t.dirtyParams[t.calleeOf(n)] {
				if p < len(n.Args) {
					markIdent(n.Args[p])
				}
			}
		}
		return true
	})
	if fn != nil {
		t.dirtyParams[fn] = dirty
	}

	// rebinds records calls of the shape `x = f(...)` / `x := f(...)` with
	// their target; returnCalls records calls returned directly.
	rebinds := map[*ast.CallExpr]types.Object{}
	returnCalls := map[*ast.CallExpr]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == 1 && len(n.Rhs) == 1 {
				if lhs, ok := n.Lhs[0].(*ast.Ident); ok {
					if call, ok := unparen(n.Rhs[0]).(*ast.CallExpr); ok {
						if n.Tok == token.DEFINE {
							rebinds[call] = info.Defs[lhs]
						} else {
							rebinds[call] = info.Uses[lhs]
						}
					}
				}
			}
		case *ast.ReturnStmt:
			if len(n.Results) == 1 {
				if call, ok := unparen(n.Results[0]).(*ast.CallExpr); ok {
					returnCalls[call] = true
				}
			}
		}
		return true
	})

	// aliasReturns summary: which parameters may the result alias? In
	// accepted programs a local slice never aliases a parameter (any bind
	// that would create such an alias is rejected below), so returning a
	// local is safe and only parameter names and returned calls matter.
	if fn != nil {
		sig := fn.Type().(*types.Signature)
		if sig.Results().Len() == 1 && t.classify(sig.Results().At(0).Type(), fn.Pos()).depth > 0 {
			ret := map[int]bool{}
			ast.Inspect(body, func(n ast.Node) bool {
				rs, ok := n.(*ast.ReturnStmt)
				if !ok || len(rs.Results) != 1 {
					return true
				}
				switch r := unparen(rs.Results[0]).(type) {
				case *ast.Ident:
					if i, ok := paramIdx[info.Uses[r]]; ok {
						ret[i] = true
					}
				case *ast.CallExpr:
					objs, external := t.resultAliases(r)
					if external {
						t.errf(rs.Pos(), "returns a slice that may alias a field or slice element")
					}
					for o := range objs {
						if i, ok := paramIdx[o]; ok {
							ret[i] = true
						}
					}
				case *ast.IndexExpr, *ast.SelectorExpr:
					t.errf(rs.Pos(), "returns an alias of a slice element or field")
				}
				return true
			})
			if len(ret) > 0 {
				t.aliasReturns[fn] = ret
			}
		}
	}

	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee := t.calleeOf(call)

		// Written positions: fresh value or `x = f(..., x)`, and the
		// rebound variable must not appear as any other argument (Go's f
		// would see writes through both names, the translation would not).
		for p := range t.dirtyParams[callee] {
			if p >= len(call.Args) {
				continue
			}
			switch arg := unparen(call.Args[p]).(type) {
			case *ast.CompositeLit:
				// Fresh value: nothing else observes its backing array.
			case *ast.CallExpr:
				if objs, external := t.resultAliases(arg); external || len(objs) > 0 {
					t.errf(call.Args[p].Pos(),
						"%s writes the elements of this argument, whose backing array is aliased elsewhere",
						callee.Name())
				}
			case *ast.Ident:
				obj := info.Uses[arg]
				if obj == nil || rebinds[call] != obj {
					t.errf(arg.Pos(),
						"%s writes the elements of this argument, which Go callers observe through aliasing but the translation does not — use the form %s = %s(..., %s)",
						callee.Name(), arg.Name, callee.Name(), arg.Name)
				}
				for j, other := range call.Args {
					if j == p {
						continue
					}
					if id, ok := unparen(other).(*ast.Ident); ok && info.Uses[id] == obj {
						t.errf(other.Pos(),
							"%s is passed to %s more than once while %s writes its elements — Go sees those writes through both parameters, the translation does not",
							arg.Name, callee.Name(), callee.Name())
					}
				}
			default:
				t.errf(call.Args[p].Pos(),
					"%s writes the elements of this argument — pass a variable in the form x = %s(..., x) or a fresh value",
					callee.Name(), callee.Name())
			}
		}

		// Aliasing results: a result that may alias an argument must be
		// bound back to that same variable (a returned call is handled by
		// the summary above).
		if returnCalls[call] {
			return true
		}
		objs, external := t.resultAliases(call)
		if external {
			t.errf(call.Pos(), "the result of %s may alias a field or slice element", callee.Name())
		}
		for o := range objs {
			if o != rebinds[call] {
				t.errf(call.Pos(),
					"the result of %s may alias %s — bind it back to the same variable (%s = %s(..., %s)) so the backing array keeps a single name",
					callee.Name(), o.Name(), o.Name(), callee.Name(), o.Name())
			}
		}
		return true
	})
}

func (t *translator) newFuncTr() *funcTr {
	return &funcTr{
		t:      t,
		indent: 1,
		names:  map[types.Object]string{},
		muts:   map[types.Object]bool{},
	}
}

// translateDefine translates the circuit's Define method into `def circuit`.
// Struct fields become Lean parameters.
func (t *translator) translateDefine() string {
	fd := t.findDefine()
	f := t.newFuncTr()
	f.isMain = true

	if names := fd.Recv.List[0].Names; len(names) > 0 {
		f.recv = t.pkg.TypesInfo.Defs[names[0]]
	}
	params := fd.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 || !isAPI(t.pkg.TypesInfo.TypeOf(params[0].Type)) {
		t.errf(fd.Pos(), "Define must take a single frontend.API parameter")
	}
	f.api = t.pkg.TypesInfo.Defs[params[0].Names[0]]

	obj := t.pkg.Types.Scope().Lookup(t.cfg.Circuit)
	if obj == nil {
		t.errf(fd.Pos(), "struct %s not found", t.cfg.Circuit)
	}
	st, ok := obj.Type().Underlying().(*types.Struct)
	if !ok {
		t.errf(fd.Pos(), "%s is not a struct", t.cfg.Circuit)
	}
	var binders []string
	for i := 0; i < st.NumFields(); i++ {
		fld := st.Field(i)
		k := t.classify(fld.Type(), fld.Pos())
		name := sanitize(fld.Name())
		f.names[fld] = name
		binders = append(binders, fmt.Sprintf("(%s : %s)", name, k.leanType()))
	}

	f.scanMut(fd.Body)
	f.block(fd.Body.List, false, nil)
	t.analyzeEffects(nil, fd.Body, []types.Object{f.api})
	return fmt.Sprintf("def circuit %s : Circuit Unit := do\n%s",
		strings.Join(binders, " "), strings.Join(f.lines, "\n"))
}

// translateFunc translates a package-local helper function on demand and
// returns its Lean name. Callees are emitted before callers.
func (t *translator) translateFunc(fn *types.Func, pos token.Pos) string {
	if name, ok := t.funcNames[fn]; ok {
		return name
	}
	if t.inFlight[fn] {
		t.errf(pos, "recursive functions are not supported: %s", fn.Name())
	}
	fd := t.findFuncDecl(fn)
	if fd == nil {
		t.errf(pos, "no source for function %s — register it as a blackbox", fn.Name())
	}
	sig := fn.Type().(*types.Signature)
	if sig.Variadic() {
		t.errf(fd.Pos(), "variadic functions are not supported: %s", fn.Name())
	}

	t.inFlight[fn] = true
	f := t.newFuncTr()

	var binders []string
	var paramObjs []types.Object
	for _, field := range fd.Type.Params.List {
		typ := t.pkg.TypesInfo.TypeOf(field.Type)
		for _, nameId := range field.Names {
			obj := t.pkg.TypesInfo.Defs[nameId]
			paramObjs = append(paramObjs, obj)
			if isAPI(typ) {
				f.api = obj
				continue
			}
			k := t.classify(typ, field.Pos())
			name := sanitize(nameId.Name)
			f.names[obj] = name
			binders = append(binders, fmt.Sprintf("(%s : %s)", name, k.leanType()))
		}
	}

	resType := "Unit"
	switch sig.Results().Len() {
	case 0:
	case 1:
		k := t.classify(sig.Results().At(0).Type(), fd.Pos())
		f.result = &k
		resType = k.leanTypeParen()
	default:
		t.errf(fd.Pos(), "multiple return values are not supported: %s", fn.Name())
	}

	f.scanMut(fd.Body)
	// Parameters reassigned in the body get shadowed by a mutable binding.
	var mutParams []string
	for _, field := range fd.Type.Params.List {
		for _, nameId := range field.Names {
			obj := t.pkg.TypesInfo.Defs[nameId]
			if name, ok := f.names[obj]; ok && f.muts[obj] {
				mutParams = append(mutParams, name)
			}
		}
	}
	var prologue func()
	if len(mutParams) > 0 {
		prologue = func() {
			for _, n := range mutParams {
				f.emit(fmt.Sprintf("let mut %s := %s", n, n))
			}
			f.last = lastLet
		}
	}
	f.block(fd.Body.List, false, prologue)
	t.analyzeEffects(fn, fd.Body, paramObjs)

	name := t.uniqueName(fn.Name())
	t.funcNames[fn] = name
	def := fmt.Sprintf("def %s %s : Circuit %s := do\n%s",
		name, strings.Join(binders, " "), resType, strings.Join(f.lines, "\n"))
	t.defs = append(t.defs, def)
	delete(t.inFlight, fn)
	return name
}

// ensureAxiom emits the axiomatized opaque predicate and monadic wrapper for
// a blackboxed function.
func (t *translator) ensureAxiom(leanName string, fn *types.Func, pos token.Pos) {
	if t.axiomSeen[leanName] {
		return
	}
	t.axiomSeen[leanName] = true
	t.usedNames[leanName] = true
	t.usedNames[leanName+"_pred"] = true

	sig := fn.Type().(*types.Signature)
	var binders, predArgTypes, argNames []string
	for i := 0; i < sig.Params().Len(); i++ {
		p := sig.Params().At(i)
		if isAPI(p.Type()) {
			continue
		}
		k := t.classify(p.Type(), pos)
		name := sanitize(p.Name())
		if name == "" || name == "_" {
			name = fmt.Sprintf("x%d", i)
		}
		binders = append(binders, fmt.Sprintf("(%s : %s)", name, k.leanType()))
		predArgTypes = append(predArgTypes, k.leanType())
		argNames = append(argNames, name)
	}

	var res *kind
	switch sig.Results().Len() {
	case 0:
	case 1:
		k := t.classify(sig.Results().At(0).Type(), pos)
		res = &k
	default:
		t.errf(pos, "blackbox %s: multiple return values are not supported", fn.Name())
	}

	var axiom, def string
	if res == nil {
		axiom = fmt.Sprintf("axiom %s_pred : %s → Prop", leanName, strings.Join(predArgTypes, " → "))
		def = fmt.Sprintf("def %s %s : Circuit Unit := fun k =>\n  %s_pred %s ∧ k ()",
			leanName, strings.Join(binders, " "), leanName, strings.Join(argNames, " "))
	} else {
		axiom = fmt.Sprintf("axiom %s_pred : %s → %s → Prop",
			leanName, strings.Join(predArgTypes, " → "), res.leanType())
		def = fmt.Sprintf("def %s %s : Circuit %s := fun k =>\n  ∃ out, %s_pred %s out ∧ k out",
			leanName, strings.Join(binders, " "), res.leanTypeParen(), leanName, strings.Join(argNames, " "))
	}
	t.axioms = append(t.axioms, axiom+"\n"+def)
}

func (t *translator) prelude() string {
	order := t.cfg.Field.ScalarField()
	return fmt.Sprintf(`import Mathlib.Data.ZMod.Basic

set_option linter.unusedVariables false

namespace %s

def Order : ℕ := 0x%s
abbrev F := ZMod Order
variable [Fact (Nat.Prime Order)]
instance : Inhabited F := ⟨0⟩

/-- The values taken by the variable of a Go loop
    for i := lo; i < hi; i++ (empty when hi ≤ lo). -/
def goRange (lo hi : Int64) : List Int64 :=
  (List.range (hi.toInt - lo.toInt).toNat).map (fun k => lo + Int64.ofNat k)

/-- The circuit-semantics monad: a continuation into Prop. -/
def Circuit (α : Type) : Type := (α → Prop) → Prop

instance : Monad Circuit where
  pure a := fun k => k a
  bind m f := fun k => m fun a => f a k

/-- A circuit is satisfiable iff running it bottoms out in True. -/
def Circuit.run {α : Type} (c : Circuit α) : Prop := c fun _ => True

namespace Gates

def add (a b : F) : F := a + b
def sub (a b : F) : F := a - b
def mul (a b : F) : F := a * b
def neg (a : F) : F := -a
def select (s a b : F) : F := s * a + (1 - s) * b
def isZero (a : F) : F := if a = 0 then 1 else 0
def xor (a b : F) : F := a + b - 2 * a * b
def and (a b : F) : F := a * b
def or (a b : F) : F := a + b - a * b
def lookup2 (b0 b1 i0 i1 i2 i3 : F) : F :=
  (1 - b0) * (1 - b1) * i0 + b0 * (1 - b1) * i1 + (1 - b0) * b1 * i2 + b0 * b1 * i3
def fromBinary (bs : List F) : F := bs.foldr (fun b acc => b + 2 * acc) 0
def eq (a b : F) : Circuit Unit := fun k => a = b ∧ k ()
def ne (a b : F) : Circuit Unit := fun k => a ≠ b ∧ k ()
def isBool (a : F) : Circuit Unit := fun k => (a = 0 ∨ a = 1) ∧ k ()
def le (a b : F) : Circuit Unit := fun k => a.val ≤ b.val ∧ k ()
def div (a b : F) : Circuit F := fun k => b ≠ 0 ∧ k (a / b)
def divUnchecked (a b : F) : Circuit F := fun k => ∃ c, c * b = a ∧ k c
def inv (a : F) : Circuit F := fun k => a ≠ 0 ∧ k a⁻¹
def toBinary (a : F) (n : Nat) : Circuit (List F) := fun k =>
  ∃ bs : List F, bs.length = n ∧ (∀ b ∈ bs, b = 0 ∨ b = 1) ∧ fromBinary bs = a ∧ k bs

end Gates`, t.cfg.Namespace, order.Text(16))
}
