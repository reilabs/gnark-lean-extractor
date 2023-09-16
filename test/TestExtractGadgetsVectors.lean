import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace MultipleGadgetsVectors

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order

def VectorGadget_3_3_3_3 (In_1: Vector F 3) (In_2: Vector F 3) (Nested: Vector (Vector F 3) 3) (k: Vector F 3 -> Prop): Prop :=
    ∃_ignored_, _ignored_ = Gates.mul In_1[0] In_2[0] ∧
    ∃_ignored_, _ignored_ = Gates.mul In_1[1] In_2[1] ∧
    ∃gate_2, gate_2 = Gates.mul In_1[2] In_2[2] ∧
    k vec![gate_2, gate_2, gate_2]

def ReturnItself_3_3 (In_1: Vector F 3) (Out: Vector F 3) (k: Vector F 3 -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.mul In_1[0] In_1[0] ∧
    ∃gate_1, gate_1 = Gates.mul In_1[1] In_1[1] ∧
    ∃gate_2, gate_2 = Gates.mul In_1[2] In_1[2] ∧
    k vec![gate_0, gate_1, gate_2]

def OptimisedVectorGadget (In: F) (k: Vector F 3 -> Prop): Prop :=
    ∃gate_0, Gates.to_binary In 3 gate_0 ∧
    k gate_0

end MultipleGadgetsVectors