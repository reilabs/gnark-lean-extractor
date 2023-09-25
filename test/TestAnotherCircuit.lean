import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace AnotherCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order

def IntArrayGadget_4 (In: Vector F 4) (k: Vector F 3 -> Prop): Prop :=
    ∃gate_0, Gates.from_binary In gate_0 ∧
    ∃_ignored_, _ignored_ = Gates.mul (0:F) (36:F) ∧
    k vec![gate_0, gate_0, gate_0]

def circuit (In: Vector F 4): Prop :=
    IntArrayGadget_4 In fun gate_0 =>
    ∃_ignored_, Gates.from_binary vec![gate_0[1], gate_0[2]] _ignored_ ∧
    ∃_ignored_, Gates.from_binary vec![gate_0[0], gate_0[1]] _ignored_ ∧
    ∃_ignored_, Gates.from_binary gate_0 _ignored_ ∧
    True

end AnotherCircuit