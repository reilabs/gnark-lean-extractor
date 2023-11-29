import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace MultipleCircuits

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark_8 Order

def VectorGadget_3_3_3_3 (In_1: Vector F 3) (In_2: Vector F 3) (Nested: Vector (Vector F 3) 3) (k: Vector F 3 -> Prop): Prop :=
    ∃_ignored_, _ignored_ = Gates.mul In_1[0] In_2[0] ∧
    ∃_ignored_, _ignored_ = Gates.mul In_1[1] In_2[1] ∧
    ∃gate_2, gate_2 = Gates.mul In_1[2] In_2[2] ∧
    k vec![gate_2, gate_2, gate_2]

def DummyHash (In_1: F) (In_2: F) (k: F -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.mul In_1 In_2 ∧
    k gate_0

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

def MyWidget_6 (Test_1: F) (Test_2: F) (k: F -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.add Test_1 Test_2 ∧
    ∃gate_1, gate_1 = Gates.mul Test_1 Test_2 ∧
    ∃gate_2, Gates.div gate_0 gate_1 gate_2 ∧
    Gates.is_bool (6:F) ∧
    k gate_2

def MySecondWidget_6 (Test_1: F) (Test_2: F) : Prop :=
    ∃gate_0, gate_0 = Gates.mul Test_1 Test_2 ∧
    MyWidget_6 Test_1 Test_2 fun gate_1 =>
    ∃_ignored_, _ignored_ = Gates.mul gate_0 gate_1 ∧
    True

def ToBinaryCircuit_3_3 (In: F) (Out: F) (Double: Vector (Vector F 3) 3): Prop :=
    ∃gate_0, Gates.to_binary In 3 gate_0 ∧
    ∃gate_1, Gates.to_binary Out 3 gate_1 ∧
    ∃_ignored_, _ignored_ = Gates.add Double[2][2] Double[1][1] ∧
    ∃_ignored_, _ignored_ = Gates.add _ignored_ Double[0][0] ∧
    ∃_ignored_, _ignored_ = Gates.mul gate_0[1] gate_1[1] ∧
    VectorGadget_3_3_3_3 Double[2] Double[0] Double fun gate_4 =>
    ∃_ignored_, _ignored_ = Gates.mul gate_4[2] gate_4[1] ∧
    True

def MerkleRecover_20_20 (Root: F) (Element: F) (Path: Vector F 20) (Proof: Vector F 20): Prop :=
    DummyHash Element Proof[0] fun gate_0 =>
    DummyHash Proof[0] Element fun gate_1 =>
    ∃gate_2, Gates.select Path[0] gate_1 gate_0 gate_2 ∧
    DummyHash gate_2 Proof[1] fun gate_3 =>
    DummyHash Proof[1] gate_2 fun gate_4 =>
    ∃gate_5, Gates.select Path[1] gate_4 gate_3 gate_5 ∧
    DummyHash gate_5 Proof[2] fun gate_6 =>
    DummyHash Proof[2] gate_5 fun gate_7 =>
    ∃gate_8, Gates.select Path[2] gate_7 gate_6 gate_8 ∧
    DummyHash gate_8 Proof[3] fun gate_9 =>
    DummyHash Proof[3] gate_8 fun gate_10 =>
    ∃gate_11, Gates.select Path[3] gate_10 gate_9 gate_11 ∧
    DummyHash gate_11 Proof[4] fun gate_12 =>
    DummyHash Proof[4] gate_11 fun gate_13 =>
    ∃gate_14, Gates.select Path[4] gate_13 gate_12 gate_14 ∧
    DummyHash gate_14 Proof[5] fun gate_15 =>
    DummyHash Proof[5] gate_14 fun gate_16 =>
    ∃gate_17, Gates.select Path[5] gate_16 gate_15 gate_17 ∧
    DummyHash gate_17 Proof[6] fun gate_18 =>
    DummyHash Proof[6] gate_17 fun gate_19 =>
    ∃gate_20, Gates.select Path[6] gate_19 gate_18 gate_20 ∧
    DummyHash gate_20 Proof[7] fun gate_21 =>
    DummyHash Proof[7] gate_20 fun gate_22 =>
    ∃gate_23, Gates.select Path[7] gate_22 gate_21 gate_23 ∧
    DummyHash gate_23 Proof[8] fun gate_24 =>
    DummyHash Proof[8] gate_23 fun gate_25 =>
    ∃gate_26, Gates.select Path[8] gate_25 gate_24 gate_26 ∧
    DummyHash gate_26 Proof[9] fun gate_27 =>
    DummyHash Proof[9] gate_26 fun gate_28 =>
    ∃gate_29, Gates.select Path[9] gate_28 gate_27 gate_29 ∧
    DummyHash gate_29 Proof[10] fun gate_30 =>
    DummyHash Proof[10] gate_29 fun gate_31 =>
    ∃gate_32, Gates.select Path[10] gate_31 gate_30 gate_32 ∧
    DummyHash gate_32 Proof[11] fun gate_33 =>
    DummyHash Proof[11] gate_32 fun gate_34 =>
    ∃gate_35, Gates.select Path[11] gate_34 gate_33 gate_35 ∧
    DummyHash gate_35 Proof[12] fun gate_36 =>
    DummyHash Proof[12] gate_35 fun gate_37 =>
    ∃gate_38, Gates.select Path[12] gate_37 gate_36 gate_38 ∧
    DummyHash gate_38 Proof[13] fun gate_39 =>
    DummyHash Proof[13] gate_38 fun gate_40 =>
    ∃gate_41, Gates.select Path[13] gate_40 gate_39 gate_41 ∧
    DummyHash gate_41 Proof[14] fun gate_42 =>
    DummyHash Proof[14] gate_41 fun gate_43 =>
    ∃gate_44, Gates.select Path[14] gate_43 gate_42 gate_44 ∧
    DummyHash gate_44 Proof[15] fun gate_45 =>
    DummyHash Proof[15] gate_44 fun gate_46 =>
    ∃gate_47, Gates.select Path[15] gate_46 gate_45 gate_47 ∧
    DummyHash gate_47 Proof[16] fun gate_48 =>
    DummyHash Proof[16] gate_47 fun gate_49 =>
    ∃gate_50, Gates.select Path[16] gate_49 gate_48 gate_50 ∧
    DummyHash gate_50 Proof[17] fun gate_51 =>
    DummyHash Proof[17] gate_50 fun gate_52 =>
    ∃gate_53, Gates.select Path[17] gate_52 gate_51 gate_53 ∧
    DummyHash gate_53 Proof[18] fun gate_54 =>
    DummyHash Proof[18] gate_53 fun gate_55 =>
    ∃gate_56, Gates.select Path[18] gate_55 gate_54 gate_56 ∧
    DummyHash gate_56 Proof[19] fun gate_57 =>
    DummyHash Proof[19] gate_56 fun gate_58 =>
    ∃gate_59, Gates.select Path[19] gate_58 gate_57 gate_59 ∧
    Gates.eq gate_59 Root ∧
    True

def TwoGadgets_11 (In_1: F) (In_2: F): Prop :=
    ∃gate_0, gate_0 = Gates.add In_1 In_2 ∧
    ∃gate_1, gate_1 = Gates.mul In_1 In_2 ∧
    MySecondWidget_11 gate_0 gate_1 ∧
    True

def TwoGadgets_6 (In_1: F) (In_2: F): Prop :=
    ∃gate_0, gate_0 = Gates.add In_1 In_2 ∧
    ∃gate_1, gate_1 = Gates.mul In_1 In_2 ∧
    MySecondWidget_6 gate_0 gate_1 ∧
    True

end MultipleCircuits