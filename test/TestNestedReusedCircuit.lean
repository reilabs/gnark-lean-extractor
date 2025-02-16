import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace NestedReusedCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark8 Order



def circuit (N1_In1: List.Vector F 1) (N2_In1: List.Vector F 1): Prop :=
    ∃gate_0, gate_0 = Gates.add N1_In1[0] N2_In1[0] ∧
    Gates.eq gate_0 (0:F) ∧
    True

end NestedReusedCircuit