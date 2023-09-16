import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace DummyCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order



def circuit (In_1: F) (In_2: F) (Out: F): Prop :=
    ∃gate_0, gate_0 = Gates.add In_1 In_2 ∧
    Gates.eq gate_0 Out ∧
    True

end DummyCircuit