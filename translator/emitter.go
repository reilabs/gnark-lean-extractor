package translator

// emitter owns everything the translator emits: the shared name allocator,
// the per-decl registries, and the three output sections. It has no
// dependency on Config, packages.Package, or type inference — it is purely
// a bookkeeping surface, so registries and orchestration stay separable.
type emitter struct {
	alloc     *nameAlloc
	structReg *structRegistry
	opaqueReg *opaqueRegistry
	axiomReg  *axiomRegistry
	pkgVarReg *pkgVarRegistry
	funcReg   *funcRegistry

	// Three output sections, in the order they appear in the emitted Lean
	// file. Registries append into these through emit callbacks wired at
	// construction.
	structs []string // struct decls + opaque-type axioms
	axioms  []string // blackbox / gadget axioms
	defs    []string // package-var defs + translated helper funcs
}

func newEmitter() *emitter {
	e := &emitter{
		alloc:   newNameAlloc(),
		funcReg: newFuncRegistry(),
	}
	pushStruct := func(d string) { e.structs = append(e.structs, d) }
	pushAxiom := func(d string) { e.axioms = append(e.axioms, d) }
	pushDef := func(d string) { e.defs = append(e.defs, d) }
	e.structReg = newStructRegistry(e.alloc, pushStruct)
	e.opaqueReg = newOpaqueRegistry(e.alloc, pushStruct)
	e.axiomReg = newAxiomRegistry(e.alloc, pushAxiom)
	e.pkgVarReg = newPkgVarRegistry(e.alloc, pushDef)
	return e
}
