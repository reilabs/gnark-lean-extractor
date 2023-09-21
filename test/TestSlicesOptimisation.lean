import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace SlicesOptimisation

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order

def SlicesGadget_3_2_4_3_2 (TwoDim: Vector (Vector F 3) 2) (ThreeDim: Vector (Vector (Vector F 4) 3) 2) (k: Vector F 7 -> Prop): Prop :=
    k vec![ThreeDim[0][0][0], ThreeDim[0][0][1], ThreeDim[0][0][2], ThreeDim[0][0][3], TwoDim[0][0], TwoDim[0][1], TwoDim[0][2]]

def SlicesGadget_1_2_4_3_3 (TwoDim: Vector (Vector F 1) 2) (ThreeDim: Vector (Vector (Vector F 4) 3) 3) (k: Vector F 5 -> Prop): Prop :=
    k vec![ThreeDim[0][0][0], ThreeDim[0][0][1], ThreeDim[0][0][2], ThreeDim[0][0][3], TwoDim[0][0]]

def TwoSlices_3_2 (TwoDim: Vector (Vector F 3) 2) (k: Vector (Vector F 3) 2 -> Prop): Prop :=
    k TwoDim

def ThreeSlices_4_3_2 (ThreeDim: Vector (Vector (Vector F 4) 3) 2) (k: Vector (Vector (Vector F 4) 3) 2 -> Prop): Prop :=
    k ThreeDim

def circuit (Test: F) (Id: Vector F 3) (TwoDim: Vector (Vector F 3) 2) (ThreeDim: Vector (Vector (Vector F 4) 3) 2): Prop :=
    SlicesGadget_3_2_4_3_2 TwoDim ThreeDim fun _ =>
    SlicesGadget_3_2_4_3_2 vec![TwoDim[1], TwoDim[0]] vec![vec![ThreeDim[1][0], ThreeDim[1][1], ThreeDim[1][2]], vec![ThreeDim[0][0], ThreeDim[0][1], ThreeDim[0][2]]] fun _ =>
    SlicesGadget_1_2_4_3_3 vec![vec![TwoDim[1][1]], vec![TwoDim[1][0]]] vec![vec![ThreeDim[1][0], ThreeDim[1][1], ThreeDim[1][2]], vec![ThreeDim[0][0], ThreeDim[0][1], ThreeDim[0][2]], vec![ThreeDim[1][0], ThreeDim[1][1], ThreeDim[1][2]]] fun _ =>
    SlicesGadget_3_2_4_3_2 vec![TwoDim[1], vec![TwoDim[1][0], TwoDim[0][0], TwoDim[1][1]]] ThreeDim fun _ =>
    TwoSlices_3_2 TwoDim fun _ =>
    ThreeSlices_4_3_2 ThreeDim fun _ =>
    True

end SlicesOptimisation