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
	// OpaqueTypes maps fully-qualified Go type names ("pkg/path.Type") to
	// Lean type names.
	OpaqueTypes map[string]string
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

	// Three output sections, in the order they appear in the emitted Lean
	// file. Registries below append into these directly through emit
	// callbacks wired at construction.
	structs []string // struct decls + opaque-type axioms
	axioms  []string // blackbox / gadget axioms
	defs    []string // package-var defs + translated helper funcs

	// Registries wrap the memoization + emission for each kind of top-level
	// decl. See registries.go for the shared invariants (reserve-before-
	// emit for recursion safety, etc.).
	alloc     *nameAlloc
	structReg *structRegistry
	opaqueReg *opaqueRegistry
	axiomReg  *axiomRegistry
	pkgVarReg *pkgVarRegistry
	funcReg   *funcRegistry
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
		cfg:     cfg,
		pkg:     pkg,
		alloc:   newNameAlloc(),
		funcReg: newFuncRegistry(),
	}
	// Registries share the "structs" section for struct decls and opaque
	// axioms; funcs and package vars share the "defs" section.
	pushStruct := func(d string) { t.structs = append(t.structs, d) }
	pushAxiom := func(d string) { t.axioms = append(t.axioms, d) }
	pushDef := func(d string) { t.defs = append(t.defs, d) }
	t.structReg = newStructRegistry(t.alloc, pushStruct)
	t.opaqueReg = newOpaqueRegistry(t.alloc, pushStruct)
	t.axiomReg = newAxiomRegistry(t.alloc, pushAxiom)
	t.pkgVarReg = newPkgVarRegistry(t.alloc, pushDef)
	for _, r := range []string{
		"circuit", "Gates", "F", "Order", "Circuit", "Int64", "goRange",
	} {
		t.alloc.reserveExact(r)
	}
	// Reserve the outer namespace name too.
	t.alloc.reserveExact(cfg.Namespace)

	circuitDef := t.translateDefine()

	var b strings.Builder
	b.WriteString(t.prelude())
	for _, s := range t.structs {
		b.WriteString("\n\n")
		b.WriteString(s)
	}
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
	// When the circuit references an opaque type, wrap the whole body in a
	// noncomputable section.
	if t.opaqueReg.any() {
		b.WriteString(fmt.Sprintf("\n\nend %s\n", cfg.Namespace))
		out := strings.Replace(b.String(), "namespace "+cfg.Namespace,
			"namespace "+cfg.Namespace+"\n\nnoncomputable section", 1)
		out = strings.Replace(out, "end "+cfg.Namespace, "end\n\nend "+cfg.Namespace, 1)
		return out, nil
	}
	b.WriteString(fmt.Sprintf("\n\nend %s\n", cfg.Namespace))
	return b.String(), nil
}

func (t *translator) errf(pos token.Pos, format string, args ...any) {
	panic(translateError{t.pkg.Fset.Position(pos), fmt.Sprintf(format, args...)})
}

var leanReserved = map[string]bool{
	"let": true, "fun": true, "do": true, "if": true, "then": true,
	"else": true, "for": true, "in": true, "mut": true, "return": true,
	"pure": true, "match": true, "with": true, "end": true, "def": true,
	"axiom": true, "namespace": true, "open": true, "k": true, "out": true,
	"F": true, "Order": true, "Gates": true, "Circuit": true, "circuit": true,
	"public": true, "private": true, "protected": true, "section": true,
	"variable": true, "instance": true, "structure": true, "class": true,
	"theorem": true, "lemma": true, "example": true, "import": true,
	"where": true, "extends": true, "deriving": true,
}

func sanitize(name string) string {
	if leanReserved[name] {
		return name + "_"
	}
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
			if ok && t.pkg.TypesInfo.Defs[fd.Name] == fn {
				return fd
			}
		}
	}
	return nil
}

func (t *translator) newFuncBody() *funcBody {
	return &funcBody{
		t:       t,
		names:   map[types.Object]string{},
		muts:    map[types.Object]bool{},
		errVars: map[types.Object]bool{},
	}
}

// translateDefine translates the circuit's Define method into `def circuit`.
// Struct fields become Lean parameters.
func (t *translator) translateDefine() string {
	fd := t.findDefine()
	b := t.newFuncBody()
	b.isMain = true

	if names := fd.Recv.List[0].Names; len(names) > 0 {
		b.recv = t.pkg.TypesInfo.Defs[names[0]]
	}
	params := fd.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 || !isAPI(t.pkg.TypesInfo.TypeOf(params[0].Type)) {
		t.errf(fd.Pos(), "Define must take a single frontend.API parameter")
	}
	b.api = t.pkg.TypesInfo.Defs[params[0].Names[0]]

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
		b.names[fld] = name
		binders = append(binders, fmt.Sprintf("(%s : %s)", name, t.leanType(k)))
	}

	b.scanMut(fd.Body)
	b.block(fd.Body.List, nil)
	t.analyzeEffects(nil, fd.Body, []types.Object{b.api})
	body := renderBlock(block{stmts: b.stmts, allowReassignEnd: false}, 1)
	return fmt.Sprintf("def circuit %s : Circuit Unit := do\n%s",
		strings.Join(binders, " "), strings.Join(body, "\n"))
}

// translateFunc translates a package-local helper function on demand and
// returns its Lean name. Callees are emitted before callers.
func (t *translator) translateFunc(fn *types.Func, pos token.Pos) string {
	slot := t.funcReg.slot(fn)
	if slot.done {
		return slot.leanName
	}
	if slot.inFlight {
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

	slot.inFlight = true
	b := t.newFuncBody()

	var binders []string
	var paramObjs []types.Object

	// Method receiver: prepend a `(self : Recv)` binder, register the
	// receiver ident so the body may refer to it, and remember the named
	// struct so the def gets namespace-qualified below. Pointer receivers
	// are erased — the translation is value-semantic, so any receiver-side
	// mutation would surface as a rejected field write elsewhere.
	var recvNamed *types.Named
	if fd.Recv != nil {
		recvType := t.pkg.TypesInfo.TypeOf(fd.Recv.List[0].Type)
		rk := t.classify(recvType, fd.Recv.Pos())
		if rk.base != baseStruct || rk.depth != 0 {
			t.errf(fd.Recv.Pos(), "unsupported receiver type for %s", fn.Name())
		}
		recvNamed = rk.named
		recvName := "self"
		if names := fd.Recv.List[0].Names; len(names) > 0 && names[0].Name != "_" {
			recvName = sanitize(names[0].Name)
			obj := t.pkg.TypesInfo.Defs[names[0]]
			b.names[obj] = recvName
		}
		binders = append(binders, fmt.Sprintf("(%s : %s)", recvName, t.leanType(rk)))
	}

	for _, field := range fd.Type.Params.List {
		typ := t.pkg.TypesInfo.TypeOf(field.Type)
		for _, nameId := range field.Names {
			obj := t.pkg.TypesInfo.Defs[nameId]
			paramObjs = append(paramObjs, obj)
			if isAPI(typ) {
				b.api = obj
				continue
			}
			k := t.classify(typ, field.Pos())
			name := sanitize(nameId.Name)
			b.names[obj] = name
			binders = append(binders, fmt.Sprintf("(%s : %s)", name, t.leanType(k)))
		}
	}

	resType := "Unit"
	results, droppedErr := stripTrailingError(sig.Results())
	b.hasErrResult = droppedErr
	if n := results.Len(); n > 0 {
		kinds := make([]kind, n)
		parts := make([]string, n)
		for i := 0; i < n; i++ {
			rt := results.At(i).Type()
			// The abstractor's `DefineGadget` convention declares its
			// return as `interface{}`; classify the actual return
			// expression's type instead.
			if isEmptyInterface(rt) && n == 1 {
				actual := findReturnExprType(fd.Body, t.pkg.TypesInfo)
				if actual == nil {
					t.errf(fd.Pos(), "cannot infer return type of %s (empty-interface signature and no return expression)", fn.Name())
				}
				rt = actual
			}
			kinds[i] = t.classify(rt, fd.Pos())
			parts[i] = t.leanType(kinds[i])
		}
		b.result = kinds
		if n == 1 {
			resType = t.leanTypeParen(kinds[0])
		} else {
			resType = "(" + strings.Join(parts, " × ") + ")"
		}
	}

	// Named return values (`func f() (x, y T)`): the body treats them as
	// zero-initialized mutable locals, and a bare `return` returns their
	// current values. Register them so the body can reference and assign
	// to them; the prologue below emits their initial bindings.
	var namedReturns []string
	if fd.Type.Results != nil {
		var idx int
		for _, field := range fd.Type.Results.List {
			for _, nameId := range field.Names {
				if nameId.Name == "_" || idx >= len(b.result) {
					idx++
					continue
				}
				obj := t.pkg.TypesInfo.Defs[nameId]
				name := sanitize(nameId.Name)
				b.names[obj] = name
				b.muts[obj] = true
				namedReturns = append(namedReturns, name)
				idx++
			}
		}
		if len(namedReturns) > 0 {
			b.namedReturns = namedReturns
		}
	}

	b.scanMut(fd.Body)
	// Parameters reassigned in the body get shadowed by a mutable binding.
	var mutParams []string
	for _, field := range fd.Type.Params.List {
		for _, nameId := range field.Names {
			obj := t.pkg.TypesInfo.Defs[nameId]
			if name, ok := b.names[obj]; ok && b.muts[obj] {
				mutParams = append(mutParams, name)
			}
		}
	}
	var prologue func()
	if len(mutParams) > 0 || len(namedReturns) > 0 {
		prologue = func() {
			// Named returns bound as zero-initialised mut locals first —
			// param shadows follow so any param that also carries a
			// named-return name still refers to itself.
			for i, n := range namedReturns {
				zero := "(0 : F)"
				if i < len(b.result) {
					zero = b.t.zero(b.result[i], nil)
				}
				b.push(letBind{name: n, rhs: zero, mut: true})
			}
			for _, n := range mutParams {
				b.push(letBind{name: n, rhs: n, mut: true})
			}
		}
	}
	b.block(fd.Body.List, prologue)
	t.analyzeEffects(fn, fd.Body, paramObjs)

	var name string
	if recvNamed != nil {
		// Method: `def <StructName>.<MethodName>` — Lean namespace
		// resolution lets call sites use `u.MethodName args` dot syntax.
		name = t.structReg.name(recvNamed) + "." + fn.Name()
		t.alloc.reserveExact(name)
	} else {
		name = t.alloc.fresh(fn.Name())
	}
	slot.leanName = name
	slot.done = true
	slot.inFlight = false
	body := renderBlock(block{stmts: b.stmts, allowReassignEnd: false}, 1)
	def := fmt.Sprintf("def %s %s : Circuit %s := do\n%s",
		name, strings.Join(binders, " "), resType, strings.Join(body, "\n"))
	t.defs = append(t.defs, def)
	return name
}

func (t *translator) prelude() string {
	order := t.cfg.Field.ScalarField()
	return fmt.Sprintf(`import Mathlib.Data.ZMod.Basic
import Mathlib.FieldTheory.Finite.Basic

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
