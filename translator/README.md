# Static circuit translator (V1)

This package is an alternative front-end to the trace-based `extractor`: it
translates gnark circuits **from Go source** into Lean 4, instead of running
them against a fake `frontend.API` and recording a flat trace.

Because the translation is static:

- **Circuits are translated as-is.** No `abstractor` gadget structs, no
  `DefineGadget`/`Call` boilerplate — plain Go helper functions become Lean
  definitions.
- **Loops survive.** Go `for` loops become Lean do-notation `for` loops; the
  output is never unrolled.
- **Sizes stay symbolic.** A `[]frontend.Variable` field becomes a `List F`
  parameter and `len(xs)` becomes `xs.length`, so a single Lean definition
  covers every instantiation — no monomorphized `f_3`/`f_5` variants.
- **gnark-std constructions can be blackboxed.** A registered function is
  emitted as an axiomatized relation between its inputs and outputs and never
  looked into.

## The Lean encoding

The old extractor's continuation-passing gadgets (`(k : F -> Prop)`) are the
continuation monad in disguise. The generated prelude makes this explicit:

```lean
def Circuit (α : Type) : Type := (α → Prop) → Prop

instance : Monad Circuit where
  pure a := fun k => k a
  bind m f := fun k => m fun a => f a k
```

so circuit semantics is ordinary do-notation, with Lean's own `let mut` and
`for` providing loop-carried state:

```lean
def circuit (Leaf : F) (Path : List F) (Root : F) : Circuit Unit := do
  let mut h := Leaf
  for i in goRange 0 (Int64.ofNat Path.length) do
    let t_0 ← Circuit.get Path i.toInt.toNat
    h ← hash2 h t_0
  Gates.eq h Root
```

Deterministic gates (`add`, `mul`, `select`, ...) are pure functions on `F`;
constraint-emitting operations (`eq`, `isBool`, `div`, `toBinary`, ...) are
`Circuit`-valued, encoding the constraint as a conjunction and nondeterminism
(hints, decompositions) as an existential. `Circuit.run c` closes the
continuation with `True`, yielding the satisfiability proposition.

## Usage

```go
out, err := translator.Translate(translator.Config{
    Dir:     "path/to/circuit/package",
    Circuit: "MerkleChain",          // struct with a Define method
    Field:   ecc.BN254,
    Blackboxes: map[string]string{
        "github.com/consensys/gnark/std/hash/mimc.NewMiMC": "MiMC",
    },
})
```

Everything reachable from `Define` inside the circuit's own package is
translated; calls that leave the package must be blackboxed, and anything
outside the supported subset fails loudly with a source position.

## Supported subset (V1)

- Struct fields and locals of type `frontend.Variable`, (nested)
  slices/arrays of it, and Go integers (mapped to Lean's `Int64`, whose
  arithmetic — including wraparound — comparisons, and truncating `/`/`%`
  are bit-exact with Go; the prelude's `goRange` reproduces Go loop
  semantics for arbitrary, including negative, bounds).
- `api` calls: `Add`, `Sub`, `Mul`, `Neg`, `Div`, `DivUnchecked`, `Inverse`,
  `Select`, `IsZero`, `Xor`, `And`, `Or`, `Lookup2`, `ToBinary`,
  `FromBinary`, and the `AssertIs*` family.
- Package-local function calls (translated, deduplicated by definition) and
  blackboxed calls. Parameters reassigned in a body are shadowed with a
  mutable binding.
- `for i := lo; i < hi; i++`, `for i, v := range xs`, `if`/`else` on
  Go-integer conditions, `len`, `make`, `append`, `xs[i] = v`, slice
  literals (`[]frontend.Variable{0, l, r}`).
- Go integer expressions in Variable positions (gnark's implicit constants,
  e.g. `api.Add(x, 3*r+j+1)`) enter the field via `.toInt`, i.e. mod p —
  matching gnark's constant conversion.

Not yet supported (translation fails with a position): methods as helpers,
recursion, multiple return values, early returns, maps, closures, arbitrary
Go outside the above.

Out-of-range indexing is bounds-guarded: `xs[i]` translates to the monadic
`Circuit.get xs i`, whose proposition is `∃ h : i < xs.length, k xs[i]` — an
index past the end makes the circuit unsatisfiable, exactly where Go panics
and builds no circuit. (Loop-range element reads, which are in bounds by
construction, still read directly.) The remaining divergences are at other
Go panic points, which Lean totalizes: division by zero yields 0, and
`make`/indexing with negative sizes clamp to 0. A Define that panics builds
no circuit, so every Go execution that constructs a circuit agrees with the
Lean semantics.

## Caveats

- The generated Lean targets Mathlib only (self-contained prelude); it is not
  yet aligned with ProvenZK's `Gates` vocabulary.
- Aliasing that Go observes but a functional translation cannot reproduce is
  **detected and rejected** with a source position rather than silently
  mistranslated:
  - a loop body reassigning a variable its own bound reads (Go re-evaluates
    the bound each iteration; element writes are allowed since they cannot
    change a length);
  - writing to a slice while ranging over it (Go iterates the backing array
    captured at entry);
  - binding a slice from an existing variable, element, or field
    (`ys := xs`);
  - passing a slice to a function that (transitively) writes its elements,
    except in the rebinding form `x = f(..., x)` or with a fresh value —
    functions carry effect summaries for this. The rebound variable may not
    appear as any other argument of the same call (Go's callee would see the
    writes through both parameters);
  - binding the result of a function that may return (an alias of) one of
    its arguments to any variable other than that same argument — functions
    carry returns-alias summaries for this, so `x = permute(api, x)` is fine
    but `ys := id(api, xs)` is rejected.

  Together these enforce the invariant the translation relies on: every
  slice backing array has at most one live name, so Go's in-place writes and
  the translation's functional updates are observationally equal.
- `TestLeanTypeCheck` elaborates every golden file with a bare `lean`
  binary (skipped when `lean` is not on PATH), substituting core-only
  stand-ins for the two Mathlib-dependent prelude lines. Checking the real
  prelude against Mathlib in CI is still open.
