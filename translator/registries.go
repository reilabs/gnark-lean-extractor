package translator

import (
	"fmt"
	"go/types"
)

// nameAlloc reserves globally-unique Lean top-level identifiers. Every
// registry that emits a decl (struct, axiom, def, opaque, package-var,
// receiver-qualified method) allocates through here so decls never collide.
type nameAlloc struct{ used map[string]bool }

func newNameAlloc() *nameAlloc { return &nameAlloc{used: map[string]bool{}} }

// reserveExact commits to a specific name. Used for names whose shape is
// dictated by the source (e.g. `StructName.DefineGadget`) rather than
// synthesized. Callers are expected to have picked a name they know won't
// collide.
func (a *nameAlloc) reserveExact(name string) { a.used[name] = true }

// fresh returns a Lean name derived from base, appending `_1`, `_2`, …
// until unclaimed. Reserves the returned name before returning.
func (a *nameAlloc) fresh(base string) string {
	name := sanitize(base)
	for i := 1; a.used[name]; i++ {
		name = fmt.Sprintf("%s_%d", sanitize(base), i)
	}
	a.used[name] = true
	return name
}

// funcSlot models a helper's translation lifecycle. It replaces two parallel
// translator maps (funcNames + inFlight): rather than one map's absence
// meaning "not yet visited" and another's presence meaning "in progress",
// the state is one explicit slot with three states —
//
//	{done:false, inFlight:false}     — not yet visited
//	{done:false, inFlight:true}      — partial (recursion is an error here)
//	{done:true,  leanName:"…"}       — translated; leanName is authoritative
type funcSlot struct {
	leanName string
	inFlight bool
	done     bool
}

// funcRegistry memoizes translation status for package-local helper funcs.
// It only tracks slots — emission of the translated function's def is
// handled by translateFunc, which appends to the shared "defs" section
// directly at the point the whole def string is ready.
type funcRegistry struct{ slots map[*types.Func]*funcSlot }

func newFuncRegistry() *funcRegistry {
	return &funcRegistry{slots: map[*types.Func]*funcSlot{}}
}

// slot returns the slot for fn, creating an empty one on first sight.
func (r *funcRegistry) slot(fn *types.Func) *funcSlot {
	s := r.slots[fn]
	if s == nil {
		s = &funcSlot{}
		r.slots[fn] = s
	}
	return s
}

// structRegistry memoizes Lean structure declarations for Go named structs.
// getOrRegister reserves the Lean name BEFORE running the build callback so
// nested/recursive emission (a struct whose field type is another struct)
// sees the reserved name. build receives the reserved name so it can
// self-reference; its return value is the full `structure … deriving …`
// decl text.
type structRegistry struct {
	names map[*types.Named]string
	alloc *nameAlloc
	emit  func(decl string)
}

func newStructRegistry(alloc *nameAlloc, emit func(decl string)) *structRegistry {
	return &structRegistry{names: map[*types.Named]string{}, alloc: alloc, emit: emit}
}

func (r *structRegistry) getOrRegister(n *types.Named, build func(leanName string) string) string {
	if name, ok := r.names[n]; ok {
		return name
	}
	name := r.alloc.fresh(n.Obj().Name())
	r.names[n] = name
	r.emit(build(name))
	return name
}

// name returns the already-registered Lean name for n, or "" if not yet
// registered. Used by ensureGadgetAxiom to look up a gadget's struct name
// without triggering registration.
func (r *structRegistry) name(n *types.Named) string { return r.names[n] }

// opaqueRegistry emits `axiom X : Type` + companion Inhabited for opaque
// types declared via Config.OpaqueTypes. Decls share the "structs" output
// section (they must precede any axiom that references them), so callers
// pass the same emit callback used by structRegistry.
type opaqueRegistry struct {
	seen  map[string]bool
	alloc *nameAlloc
	emit  func(decl string)
}

func newOpaqueRegistry(alloc *nameAlloc, emit func(decl string)) *opaqueRegistry {
	return &opaqueRegistry{seen: map[string]bool{}, alloc: alloc, emit: emit}
}

// register emits the type + Inhabited axioms for leanName on first sight.
func (r *opaqueRegistry) register(leanName string) {
	if r.seen[leanName] {
		return
	}
	r.seen[leanName] = true
	inh := leanName + "_inhabited"
	r.alloc.reserveExact(leanName)
	r.alloc.reserveExact(inh)
	r.emit(fmt.Sprintf("axiom %s : Type\naxiom %s : Inhabited %s\nattribute [instance] %s",
		leanName, inh, leanName, inh))
}

// any reports whether any opaque type has been registered. Used to decide
// whether the output should be wrapped in a `noncomputable section`.
func (r *opaqueRegistry) any() bool { return len(r.seen) > 0 }

// axiomRegistry memoizes blackbox axioms. Requested names (from
// Config.Blackboxes) are mapped through the shared allocator, so a
// collision (e.g. with the outer namespace) produces a suffixed emitted
// name; subsequent requests for the same source name return that same
// emitted name.
type axiomRegistry struct {
	seen  map[string]string // requestedName -> actual leanName
	alloc *nameAlloc
	emit  func(decl string)
}

func newAxiomRegistry(alloc *nameAlloc, emit func(decl string)) *axiomRegistry {
	return &axiomRegistry{seen: map[string]string{}, alloc: alloc, emit: emit}
}

func (r *axiomRegistry) getOrRegister(requested string, build func(leanName string) string) string {
	if actual, ok := r.seen[requested]; ok {
		return actual
	}
	actual := r.alloc.fresh(requested)
	r.seen[requested] = actual
	r.emit(build(actual))
	return actual
}

// pkgVarRegistry memoizes Lean bindings for package-level Go vars. Decls
// share the "defs" output section with translated helper funcs.
type pkgVarRegistry struct {
	names map[*types.Var]string
	alloc *nameAlloc
	emit  func(decl string)
}

func newPkgVarRegistry(alloc *nameAlloc, emit func(decl string)) *pkgVarRegistry {
	return &pkgVarRegistry{names: map[*types.Var]string{}, alloc: alloc, emit: emit}
}

func (r *pkgVarRegistry) getOrRegister(v *types.Var, build func(leanName string) string) string {
	if name, ok := r.names[v]; ok {
		return name
	}
	name := r.alloc.fresh(v.Name())
	r.names[v] = name
	r.emit(build(name))
	return name
}
