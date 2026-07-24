import Mathlib.Data.ZMod.Basic
import Mathlib.FieldTheory.Finite.Basic

set_option linter.unusedVariables false

namespace BigInt

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
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

/-- Bounds-checked list read: an out-of-range index fails every continuation,
    so the circuit is unsatisfiable exactly where Go panics (and builds no
    circuit). -/
def Circuit.get {α : Type} (xs : List α) (i : Nat) : Circuit α :=
  fun k => ∃ h : i < xs.length, k (xs[i]'h)

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

end Gates

def packageBigConst : Int := (42 : Int)

def circuit (X : F) (K : Int64) (R : F) : Circuit Unit := do
  let coeffConst := (5 : Int)
  let coeffShift := (1 : Int) * 2 ^ K.toInt.toNat
  let coeffRsh := (1024 : Int) / 2 ^ K.toInt.toNat
  let coeffMix := (((Int64.shiftLeft (1 : Int64) K)).toInt)
  let coeffCopy := packageBigConst
  let sum := Gates.add (Gates.mul X ((coeffConst) : F)) (Gates.add (Gates.add (Gates.add ((coeffShift) : F) ((coeffRsh) : F)) ((coeffMix) : F)) ((coeffCopy) : F))
  Gates.eq sum R

end BigInt
