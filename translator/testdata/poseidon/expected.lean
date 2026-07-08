import Mathlib.Data.ZMod.Basic
import Mathlib.FieldTheory.Finite.Basic

set_option linter.unusedVariables false

namespace MerkleRecover

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
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

end Gates

def sbox (x : F) : Circuit F := do
  let x2 := Gates.mul x x
  let x4 := Gates.mul x2 x2
  return Gates.mul x4 x

def mix (state : List F) : Circuit (List F) := do
  let mut out_ := List.replicate state.length (0 : F)
  for i in goRange 0 (Int64.ofNat state.length) do
    let mut acc := (0 : F)
    for j in goRange 0 (Int64.ofNat state.length) do
      acc := Gates.add acc (Gates.mul (state[j.toInt.toNat]!) (((i + (2 * j)) + 1).toInt : F))
    out_ := out_.set i.toInt.toNat acc
  return out_

def permute (state : List F) : Circuit (List F) := do
  let mut state := state
  for r in goRange 0 64 do
    for j in goRange 0 (Int64.ofNat state.length) do
      state := state.set j.toInt.toNat (Gates.add (state[j.toInt.toNat]!) ((((r * (Int64.ofNat state.length)) + j) + 1).toInt : F))
    if (r < 4 ∨ 60 ≤ r) then
      for j in goRange 0 (Int64.ofNat state.length) do
        let t_0 ← sbox (state[j.toInt.toNat]!)
        state := state.set j.toInt.toNat t_0
    else
      let t_1 ← sbox (state[0]!)
      state := state.set 0 t_1
    state ← mix state
  return state

def hash2 (l : F) (r : F) : Circuit F := do
  let mut state := [(0 : F), l, r]
  state ← permute state
  return state[0]!

def circuit (Root : F) (Element : F) (Path : List F) (Proof : List F) : Circuit Unit := do
  let mut current := Element
  for i in goRange 0 (Int64.ofNat Proof.length) do
    let left ← hash2 current (Proof[i.toInt.toNat]!)
    let right ← hash2 (Proof[i.toInt.toNat]!) current
    current := Gates.select (Path[i.toInt.toNat]!) right left
  Gates.eq current Root

end MerkleRecover
