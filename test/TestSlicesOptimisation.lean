import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace SlicesOptimisation

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order

def SlicesGadget_3_2 (Proofs: Vector (Vector F 3) 2) (k: Vector F 3 -> Prop): Prop :=
    k Proofs[0]

def SlicesGadget_1_2 (Proofs: Vector (Vector F 1) 2) (k: F -> Prop): Prop :=
    k Proofs[0][0]

def circuit (IdComms: Vector F 3) (MerkleProofs: Vector (Vector F 3) 2): Prop :=
    SlicesGadget_3_2 MerkleProofs fun _ =>
    SlicesGadget_3_2 vec![MerkleProofs[1], MerkleProofs[0]] fun _ =>
    SlicesGadget_1_2 vec![vec![MerkleProofs[1][1]], vec![MerkleProofs[1][0]]] fun _ =>
    SlicesGadget_3_2 vec![MerkleProofs[1], vec![MerkleProofs[1][0], MerkleProofs[0][0], MerkleProofs[1][1]]] fun _ =>
    True

end SlicesOptimisation