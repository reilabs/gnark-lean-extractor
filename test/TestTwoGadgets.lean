import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace TwoGadgets

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark9 Order

def MyWidget_11 (Test_1: F) (Test_2: F) (k: F -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.add Test_1 Test_2 ∧
    ∃gate_1, gate_1 = Gates.mul Test_1 Test_2 ∧
    ∃gate_2, Gates.div gate_0 gate_1 gate_2 ∧
    Gates.is_bool (11:F) ∧
    k gate_2

def MySecondWidget_11 (Test_1: F) (Test_2: F) : Prop :=
    ∃gate_0, gate_0 = Gates.mul Test_1 Test_2 ∧
    MyWidget_11 Test_1 Test_2 fun gate_1 =>
    ∃_ignored_, _ignored_ = Gates.mul gate_0 gate_1 ∧
    True

def circuit (In_1: F) (In_2: F): Prop :=
    ∃gate_0, gate_0 = Gates.add In_1 In_2 ∧
    ∃gate_1, gate_1 = Gates.mul In_1 In_2 ∧
    MySecondWidget_11 gate_0 gate_1 ∧
    True

end TwoGadgets