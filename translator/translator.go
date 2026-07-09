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
// Calls into packages outside the circuit's own package must either be listed
// under Config.WalkPackages — which extends the walk to those import-path
// prefixes — or declared as blackboxes, in which case they are emitted as
// axiomatized opaque predicates rather than translated.
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
	// WalkPackages lists import-path prefixes of packages the translator
	// should walk into (in addition to Dir's own package).
	WalkPackages []string
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

	// pkgs is the walkable-package registry keyed by *types.Package. Contains
	// the main circuit package plus every dependency whose import path
	// matches Config.WalkPackages. A callee whose types.Package is in this
	// map is a candidate for translation; anything else must be blackboxed.
	pkgs map[*types.Package]*packages.Package

	// emit owns the shared name allocator, per-decl registries, and the
	// three output sections. Translator methods coordinate the walk;
	// bookkeeping lives on the emitter.
	emit *emitter
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

	pkgRegistry, err := collectWalkable(pkg, cfg.WalkPackages)
	if err != nil {
		return "", err
	}

	t := &translator{
		cfg:  cfg,
		pkg:  pkg,
		pkgs: pkgRegistry,
		emit: newEmitter(),
	}
	for _, r := range []string{
		"circuit", "Gates", "F", "Order", "Circuit", "Int64", "goRange",
	} {
		t.emit.alloc.reserveExact(r)
	}
	// Reserve the outer namespace name too.
	t.emit.alloc.reserveExact(cfg.Namespace)

	circuitDef := t.translateDefine()

	var b strings.Builder
	b.WriteString(t.prelude())
	for _, s := range t.emit.structs {
		b.WriteString("\n\n")
		b.WriteString(s)
	}
	for _, a := range t.emit.axioms {
		b.WriteString("\n\n")
		b.WriteString(a)
	}
	for _, d := range t.emit.defs {
		b.WriteString("\n\n")
		b.WriteString(d)
	}
	b.WriteString("\n\n")
	b.WriteString(circuitDef)
	// When the circuit references an opaque type, wrap the whole body in a
	// noncomputable section.
	if t.emit.opaqueReg.any() {
		b.WriteString(fmt.Sprintf("\n\nend %s\n", cfg.Namespace))
		out := strings.Replace(b.String(), "namespace "+cfg.Namespace,
			"namespace "+cfg.Namespace+"\n\nnoncomputable section", 1)
		out = strings.Replace(out, "end "+cfg.Namespace, "end\n\nend "+cfg.Namespace, 1)
		return out, nil
	}
	b.WriteString(fmt.Sprintf("\n\nend %s\n", cfg.Namespace))
	return b.String(), nil
}

func (b *funcBody) errf(pos token.Pos, format string, args ...any) {
	panic(translateError{b.pkg.Fset.Position(pos), fmt.Sprintf(format, args...)})
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

// collectWalkable indexes main + every transitive dependency whose import
// path matches one of the WalkPackages prefixes. Each entry must have Syntax
// and TypesInfo populated (packages.Load with NeedDeps + NeedSyntax +
// NeedTypesInfo is expected to populate deps too — bail out clearly if it
// didn't for a package the caller asked us to walk).
func collectWalkable(main *packages.Package, prefixes []string) (map[*types.Package]*packages.Package, error) {
	out := map[*types.Package]*packages.Package{main.Types: main}
	seen := map[string]bool{main.PkgPath: true}
	var walk func(p *packages.Package)
	walk = func(p *packages.Package) {
		for _, imp := range p.Imports {
			if seen[imp.PkgPath] {
				continue
			}
			seen[imp.PkgPath] = true
			if walkableMatch(imp.PkgPath, prefixes) {
				if imp.Types == nil || imp.Syntax == nil || imp.TypesInfo == nil {
					// The caller asked us to walk this package but the
					// loader didn't hand us its syntax/type-info; surface it.
					continue
				}
				out[imp.Types] = imp
			}
			walk(imp)
		}
	}
	walk(main)
	// Verify every requested prefix matched at least one package.
	for _, pref := range prefixes {
		matched := false
		for _, p := range out {
			if walkableMatch(p.PkgPath, []string{pref}) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("WalkPackages prefix %q did not match any loaded dependency (make sure the main circuit package imports something under it)", pref)
		}
	}
	return out, nil
}

// walkableMatch reports whether pkgPath is equal to or nested under any of
// the given prefixes.
func walkableMatch(pkgPath string, prefixes []string) bool {
	for _, p := range prefixes {
		if pkgPath == p || strings.HasPrefix(pkgPath, p+"/") {
			return true
		}
	}
	return false
}

// findFuncDecl locates fn's AST across the walkable-package registry. The
// caller's b.pkg may not be the same as fn.Pkg() (e.g. when a same-package
// helper calls into a foreign walkable package), so we look up by
// fn.Pkg() rather than assuming b.pkg.
func (b *funcBody) findFuncDecl(fn *types.Func) *ast.FuncDecl {
	pkg := b.pkgs[fn.Pkg()]
	if pkg == nil {
		return nil
	}
	info := pkg.TypesInfo
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if ok && info.Defs[fd.Name] == fn {
				return fd
			}
		}
	}
	return nil
}

func (t *translator) newFuncBody() *funcBody {
	return &funcBody{
		cfg:     t.cfg,
		pkg:     t.pkg,
		info:    t.pkg.TypesInfo,
		pkgs:    t.pkgs,
		mainPkg: t.pkg,
		emit:    t.emit,
		names:   map[types.Object]string{},
		muts:    map[types.Object]bool{},
		errVars: map[types.Object]bool{},
	}
}

// runBody walks the AST body into b (block + analyzeEffects). Callers must
// call b.scanMut(body) beforehand — translateFunc reads b.muts to build the
// mut-param prologue, so scanning stays under caller control. fn is nil for
// Define.
func (b *funcBody) runBody(fn *types.Func, body *ast.BlockStmt, prologue func(), paramObjs []types.Object) {
	b.block(body.List, prologue)
	b.analyzeEffects(fn, body, paramObjs)
}

// renderDef formats a top-level Lean `def NAME BINDERS : Circuit RESTYPE :=
// do BODY` from a walked funcBody's stmts.
func renderDef(name string, binders []string, resType string, stmts []stmt) string {
	body := renderBlock(block{stmts: stmts, allowReassignEnd: false}, 1)
	return fmt.Sprintf("def %s %s : Circuit %s := do\n%s",
		name, strings.Join(binders, " "), resType, strings.Join(body, "\n"))
}

// translateDefine translates the circuit's Define method into `def circuit`.
// Struct fields become Lean parameters.
func (t *translator) translateDefine() string {
	fd := t.findDefine()
	b := t.newFuncBody()
	b.isMain = true

	if names := fd.Recv.List[0].Names; len(names) > 0 {
		b.recv = b.info.Defs[names[0]]
	}
	params := fd.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 || !isAPI(b.info.TypeOf(params[0].Type)) {
		b.errf(fd.Pos(), "Define must take a single frontend.API parameter")
	}
	b.api = b.info.Defs[params[0].Names[0]]

	obj := b.pkg.Types.Scope().Lookup(b.cfg.Circuit)
	if obj == nil {
		b.errf(fd.Pos(), "struct %s not found", b.cfg.Circuit)
	}
	st, ok := obj.Type().Underlying().(*types.Struct)
	if !ok {
		b.errf(fd.Pos(), "%s is not a struct", b.cfg.Circuit)
	}
	binders := make([]string, st.NumFields())
	for i := 0; i < st.NumFields(); i++ {
		fld := st.Field(i)
		binders[i] = b.bindLocal(fld.Name(), fld, fld.Type(), fld.Pos())
	}

	b.scanMut(fd.Body)
	b.runBody(nil, fd.Body, nil, []types.Object{b.api})
	return renderDef("circuit", binders, "Unit", b.stmts)
}

// translateFunc translates a package-local helper function on demand and
// returns its Lean name. Callees are emitted before callers. Called from the
// expression walker (b.call) — the receiver is the *caller's* funcBody; a
// child funcBody is spawned to walk the callee. Each phase (validate the
// slot, bind receiver / params / result / named returns / prologue, walk
// the body, allocate a name, emit the def) is a separate helper below.
func (b *funcBody) translateFunc(fn *types.Func, pos token.Pos) string {
	slot := b.emit.funcReg.slot(fn)
	if slot.done {
		return slot.leanName
	}
	fd, sig := b.checkTranslatable(fn, slot, pos)

	c := b.newChild(fn.Pkg())
	recvNamed, binders := c.bindReceiver(fd, fn.Name())
	paramBinders, paramObjs := c.bindParams(fd)
	binders = append(binders, paramBinders...)
	resType := c.inferResult(sig, fd, fn.Name())
	c.bindNamedReturns(fd)

	c.scanMut(fd.Body)
	prologue := c.buildPrologue(fd)
	c.runBody(fn, fd.Body, prologue, paramObjs)

	name := b.allocateFuncName(fn, recvNamed)
	slot.leanName = name
	slot.done = true
	slot.inFlight = false
	b.emit.defs = append(b.emit.defs, renderDef(name, binders, resType, c.stmts))
	return name
}

// newChild returns a fresh funcBody sharing b's shared translation state
// (cfg / emit / pkgs / mainPkg) with empty per-body scope. If target is
// non-nil and differs from b.pkg.Types, pkg / info are swapped to the
// target package's *packages.Package — the callee walks against its own
// syntax and type-info. Used by translateFunc to walk a callee's body
// without disturbing the caller's state.
func (b *funcBody) newChild(target *types.Package) *funcBody {
	pkg, info := b.pkg, b.info
	if target != nil && target != pkg.Types {
		if p := b.pkgs[target]; p != nil {
			pkg, info = p, p.TypesInfo
		}
	}
	return &funcBody{
		cfg:     b.cfg,
		pkg:     pkg,
		info:    info,
		pkgs:    b.pkgs,
		mainPkg: b.mainPkg,
		emit:    b.emit,
		names:   map[types.Object]string{},
		muts:    map[types.Object]bool{},
		errVars: map[types.Object]bool{},
	}
}

// checkTranslatable validates that fn is translatable — has source, isn't
// variadic, isn't already in flight (which would mean recursion). Marks the
// slot in flight on success and returns the AST decl plus signature.
func (b *funcBody) checkTranslatable(fn *types.Func, slot *funcSlot, pos token.Pos) (*ast.FuncDecl, *types.Signature) {
	if slot.inFlight {
		b.errf(pos, "recursive functions are not supported: %s", fn.Name())
	}
	fd := b.findFuncDecl(fn)
	if fd == nil {
		b.errf(pos, "no source for function %s — register it as a blackbox", fn.Name())
	}
	sig := fn.Type().(*types.Signature)
	if sig.Variadic() {
		b.errf(fd.Pos(), "variadic functions are not supported: %s", fn.Name())
	}
	slot.inFlight = true
	return fd, sig
}

// bindReceiver emits the `(self : Recv)` binder for methods, registers the
// receiver ident, and returns the named struct (for def-name qualification).
// Pointer receivers are erased — the translation is value-semantic, so any
// receiver-side mutation is caught later as a rejected field write. Returns
// (nil, nil) for non-methods.
func (b *funcBody) bindReceiver(fd *ast.FuncDecl, fnName string) (*types.Named, []string) {
	if fd.Recv == nil {
		return nil, nil
	}
	recvType := b.info.TypeOf(fd.Recv.List[0].Type)
	rk := b.classify(recvType, fd.Recv.Pos())
	if rk.base != baseStruct || rk.depth != 0 {
		b.errf(fd.Recv.Pos(), "unsupported receiver type for %s", fnName)
	}
	recvName := "self"
	var recvObj types.Object
	if names := fd.Recv.List[0].Names; len(names) > 0 && names[0].Name != "_" {
		recvName = names[0].Name
		recvObj = b.info.Defs[names[0]]
	}
	return rk.named, []string{b.bindLocal(recvName, recvObj, recvType, fd.Recv.Pos())}
}

// bindParams walks fd's parameter list, building binders for non-api params
// and stashing the api object on b. Returns the binders and the full param
// object list (in signature order, api included) that analyzeEffects needs.
func (b *funcBody) bindParams(fd *ast.FuncDecl) ([]string, []types.Object) {
	var binders []string
	var paramObjs []types.Object
	for _, field := range fd.Type.Params.List {
		typ := b.info.TypeOf(field.Type)
		for _, nameId := range field.Names {
			obj := b.info.Defs[nameId]
			paramObjs = append(paramObjs, obj)
			if isAPI(typ) {
				b.api = obj
				continue
			}
			binders = append(binders, b.bindLocal(nameId.Name, obj, typ, field.Pos()))
		}
	}
	return binders, paramObjs
}

// inferResult populates b.result and b.hasErrResult, returning the Lean
// result-type string. Handles the abstractor's `DefineGadget` convention
// (empty-interface signature) by classifying the actual return-expression
// type instead.
func (b *funcBody) inferResult(sig *types.Signature, fd *ast.FuncDecl, fnName string) string {
	results, droppedErr := stripTrailingError(sig.Results())
	b.hasErrResult = droppedErr
	n := results.Len()
	if n == 0 {
		return "Unit"
	}
	kinds := make([]kind, n)
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		rt := results.At(i).Type()
		if isEmptyInterface(rt) && n == 1 {
			actual := findReturnExprType(fd.Body, b.info)
			if actual == nil {
				b.errf(fd.Pos(), "cannot infer return type of %s (empty-interface signature and no return expression)", fnName)
			}
			rt = actual
		}
		kinds[i] = b.classify(rt, fd.Pos())
		parts[i] = b.leanType(kinds[i])
	}
	b.result = kinds
	if n == 1 {
		return b.leanTypeParen(kinds[0])
	}
	return "(" + strings.Join(parts, " × ") + ")"
}

// bindNamedReturns registers Go's named return values (`func f() (x, y T)`)
// as zero-initialized muts on b, so a bare `return` reads their current
// values and the prologue emits their initial bindings.
func (b *funcBody) bindNamedReturns(fd *ast.FuncDecl) {
	if fd.Type.Results == nil {
		return
	}
	var namedReturns []string
	var idx int
	for _, field := range fd.Type.Results.List {
		for _, nameId := range field.Names {
			if nameId.Name == "_" || idx >= len(b.result) {
				idx++
				continue
			}
			obj := b.info.Defs[nameId]
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

// buildPrologue returns the closure that inserts named-return zero bindings
// and mutable-param shadow bindings at the top of the body. nil if neither
// is needed. Must be called AFTER scanMut so b.muts reflects the body.
func (b *funcBody) buildPrologue(fd *ast.FuncDecl) func() {
	var mutParams []string
	for _, field := range fd.Type.Params.List {
		for _, nameId := range field.Names {
			obj := b.info.Defs[nameId]
			if name, ok := b.names[obj]; ok && b.muts[obj] {
				mutParams = append(mutParams, name)
			}
		}
	}
	if len(mutParams) == 0 && len(b.namedReturns) == 0 {
		return nil
	}
	return func() {
		// Named returns bound as zero-initialised mut locals first — param
		// shadows follow so any param that also carries a named-return
		// name still refers to itself.
		for i, n := range b.namedReturns {
			zero := "(0 : F)"
			if i < len(b.result) {
				zero = b.zero(b.result[i], nil)
			}
			b.push(letBind{name: n, rhs: zero, mut: true})
		}
		for _, n := range mutParams {
			b.push(letBind{name: n, rhs: n, mut: true})
		}
	}
}

// allocateFuncName returns the Lean name for fn's def. Methods get
// `<StructName>.<Method>` (reserved exactly so Lean's dot-syntax lands on
// it); free functions get a fresh unique name.
func (b *funcBody) allocateFuncName(fn *types.Func, recvNamed *types.Named) string {
	if recvNamed != nil {
		name := b.emit.structReg.name(recvNamed) + "." + fn.Name()
		b.emit.alloc.reserveExact(name)
		return name
	}
	return b.emit.alloc.fresh(fn.Name())
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

/-- Stride variant of goRange: values taken by
    for i := lo; i < hi; i += step (empty when hi ≤ lo or step ≤ 0). -/
def goRangeStep (lo hi step : Int64) : List Int64 :=
  if step.toInt ≤ 0 then []
  else
    let n := ((hi.toInt - lo.toInt + step.toInt - 1) / step.toInt).toNat
    (List.range n).map (fun k => lo + Int64.ofNat k * step)

/-- The circuit-semantics monad: a continuation into Prop. -/
def Circuit (α : Type) : Type := (α → Prop) → Prop

instance : Monad Circuit where
  pure a := fun k => k a
  bind m f := fun k => m fun a => f a k

/-- A circuit is satisfiable iff running it bottoms out in True. -/
def Circuit.run {α : Type} (c : Circuit α) : Prop := c fun _ => True

/-- Marks an unreachable code path — every continuation fails, so any
    circuit that runs through here is unsatisfiable. -/
def Circuit.panic : Circuit Unit := fun _ => False

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
