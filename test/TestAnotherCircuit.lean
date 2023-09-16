import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace AnotherCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order

def IntArrayGadget_3 (In: Vector F 3) (k: F -> Prop): Prop :=
    ∃gate_0, Gates.from_binary In gate_0 ∧
    ∃_ignored_, _ignored_ = Gates.mul (0:F) (36:F) ∧
    k gate_0

def circuit (In: Vector F 3): Prop :=
    IntArrayGadget_3 In fun _ =>
    True

end AnotherCircuit