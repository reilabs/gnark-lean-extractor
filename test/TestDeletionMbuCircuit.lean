import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace DeletionMbuCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order

def DeletionProof_2_2_3_2_2_3 (DeletionIndices: Vector F 2) (PreRoot: F) (IdComms: Vector F 2) (MerkleProofs: Vector (Vector F 3) 2) (k: F -> Prop): Prop :=
    k PreRoot

def circuit (InputHash: F) (DeletionIndices: Vector F 2) (PreRoot: F) (PostRoot: F) (IdComms: Vector F 2) (MerkleProofs: Vector (Vector F 3) 2): Prop :=
    DeletionProof_2_2_3_2_2_3 DeletionIndices PreRoot IdComms vec![vec![MerkleProofs[0][0], MerkleProofs[0][1], MerkleProofs[0][2]], vec![MerkleProofs[1][0], MerkleProofs[1][1], MerkleProofs[1][2]]] fun gate_0 =>
    Gates.eq gate_0 PostRoot ∧
    True

end DeletionMbuCircuit