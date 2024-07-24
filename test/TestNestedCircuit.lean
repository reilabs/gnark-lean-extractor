import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace NestedCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark8 Order



def circuit (N1_In1: F) (N1_In2: Vector F 5) (N2_In1: Vector (Vector F 4) 4) (N2_In2: Vector F 3): Prop :=
    ∃gate_0, gate_0 = Gates.add N1_In2[2] N2_In2[0] ∧
    Gates.eq gate_0 N1_In2[1] ∧
    True

end NestedCircuit