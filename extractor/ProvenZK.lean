import Mathlib

inductive Vect (T : Type): Nat → Type
| nil : Vect T 0
| cons : T -> Vect T n -> Vect T (Nat.succ n)

namespace Vect
  @[simp]
  def head (v: Vect T (Nat.succ n)) : T :=
    match v with
    | cons x _ => x

  @[simp]
  def tail (v: Vect T (Nat.succ n)) : Vect T n :=
    match v with
    | cons _ xs => xs

  def snoc {T n} (v: Vect T n) (x: T) : Vect T (Nat.succ n) := match v with
    | nil => cons x nil
    | cons h t => cons h (snoc t x)

  def get {T n} (v: Vect T n) (ix: Nat) (ok: ix < n) : T :=
    match v, ix with
    | cons h _, 0 => h
    | cons _ t, Nat.succ ix => get t ix (by simp_arith at ok; simp_arith; assumption)

  def reverse {T n} (v: Vect T n) : Vect T n := match v with
    | nil => nil
    | cons h t => snoc (reverse t) h

  theorem tail_of_snoc {T n} (v: Vect T (Nat.succ n)) (x: T): tail (snoc v x) = snoc (tail v) x := by
    cases v
    rfl
  
  theorem head_of_snoc {T n} (v: Vect T (Nat.succ n)) (x: T): head (snoc v x) = head v := by
    cases v
    rfl
end Vect

instance : GetElem (Vect F len) Nat F (fun (_ : Vect _ len) i => len > i) where
  getElem vect ix ok := vect.get ix ok

syntax (priority := high) "vec![" term,* "]" : term
macro_rules
  | `(vec![]) => `(Vect.nil)
  | `(vec![$x]) => `(Vect.cons $x Vect.nil)
  | `(vec![$x, $xs:term,*]) => `(Vect.cons $x (vec![$xs,*]))

set_option maxHeartbeats 100000000

def Order : ℕ := 21888242871839275222246405745257275088548364400416034343698204186575808495617
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order

namespace Gates
variable {N : Nat}
variable [Fact (Nat.Prime N)]
def add (a b : ZMod N): ZMod N := a + b
def sub (a b : ZMod N): ZMod N := a - b
def mul (a b : ZMod N): ZMod N := a * b
def inv (a : ZMod N): ZMod N := 1 / a
def iz (a : ZMod N): ZMod N := if a == 0 then 1 else 0
def eq (a b : ZMod N): Prop := a = b
def ne (a b : ZMod N): Prop := a ≠ b
end Gates
