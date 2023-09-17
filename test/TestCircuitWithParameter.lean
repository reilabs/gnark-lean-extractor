import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace CircuitWithParameter

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order

def ReturnItself_3_3 (In_1: Vector F 3) (Out: Vector F 3) (k: Vector F 3 -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.mul In_1[0] In_1[0] ∧
    ∃gate_1, gate_1 = Gates.mul In_1[1] In_1[1] ∧
    ∃gate_2, gate_2 = Gates.mul In_1[2] In_1[2] ∧
    k vec![gate_0, gate_1, gate_2]

def SliceGadget_3_3 (In_1: Vector F 3) (In_2: Vector F 3) (k: F -> Prop): Prop :=
    ∃_ignored_, _ignored_ = Gates.mul In_1[0] In_2[0] ∧
    ∃_ignored_, _ignored_ = Gates.mul In_1[1] In_2[1] ∧
    ∃_ignored_, _ignored_ = Gates.mul In_1[2] In_2[2] ∧
    ∃gate_3, Gates.from_binary In_1 gate_3 ∧
    k gate_3

def SliceGadget_2_2 (In_1: Vector F 2) (In_2: Vector F 2) (k: F -> Prop): Prop :=
    ∃_ignored_, _ignored_ = Gates.mul In_1[0] In_2[0] ∧
    ∃_ignored_, _ignored_ = Gates.mul In_1[1] In_2[1] ∧
    ∃gate_2, Gates.from_binary In_1 gate_2 ∧
    k gate_2

def circuit (In: F) (Path: Vector F 3) (Tree: Vector F 2): Prop :=
    ReturnItself_3_3 Path vec![(0:F), (0:F), (0:F)] fun gate_0 =>
    Gates.eq gate_0[1] gate_0[2] ∧
    ReturnItself_3_3 Path vec![gate_0[0], gate_0[1], gate_0[2]] fun gate_2 =>
    Gates.eq gate_2[1] gate_2[2] ∧
    ReturnItself_3_3 Path vec![gate_2[0], gate_2[1], gate_2[2]] fun gate_4 =>
    Gates.eq gate_4[1] gate_4[2] ∧
    ∃_ignored_, Gates.from_binary Path _ignored_ ∧
    ∃_ignored_, Gates.from_binary vec![gate_4[0], gate_4[1], gate_4[2]] _ignored_ ∧
    ∃_ignored_, Gates.from_binary vec![gate_4[1], gate_4[2], gate_4[0]] _ignored_ ∧
    ∃_ignored_, Gates.from_binary vec![gate_4[1], (0:F), gate_4[0]] _ignored_ ∧
    ∃_ignored_, Gates.from_binary vec![gate_4[1], gate_4[2]] _ignored_ ∧
    ∃_ignored_, Gates.to_binary In 254 _ignored_ ∧
    ∃gate_12, Gates.to_binary (20:F) 254 gate_12 ∧
    ∃gate_13, Gates.from_binary vec![gate_12[0], gate_12[1], gate_12[2], gate_12[3], gate_12[4], gate_12[5], gate_12[6], gate_12[7], gate_12[8], gate_12[9], gate_12[10], gate_12[11], gate_12[12], gate_12[13], gate_12[14], gate_12[15], gate_12[16], gate_12[17], gate_12[18], gate_12[19], gate_12[20], gate_12[21], gate_12[22], gate_12[23], gate_12[24], gate_12[25], gate_12[26], gate_12[27], gate_12[28], gate_12[29], gate_12[30], gate_12[31], gate_12[32], gate_12[33], gate_12[34], gate_12[35], gate_12[36], gate_12[37], gate_12[38], gate_12[39], gate_12[40], gate_12[41], gate_12[42], gate_12[43], gate_12[44], gate_12[45], gate_12[46], gate_12[47], gate_12[48], gate_12[49], gate_12[50], gate_12[51], gate_12[52], gate_12[53], gate_12[54], gate_12[55], gate_12[56], gate_12[57], gate_12[58], gate_12[59], gate_12[60], gate_12[61], gate_12[62], gate_12[63], gate_12[64], gate_12[65], gate_12[66], gate_12[67], gate_12[68], gate_12[69], gate_12[70], gate_12[71], gate_12[72], gate_12[73], gate_12[74], gate_12[75], gate_12[76], gate_12[77], gate_12[78], gate_12[79], gate_12[80], gate_12[81], gate_12[82], gate_12[83], gate_12[84], gate_12[85], gate_12[86], gate_12[87], gate_12[88], gate_12[89], gate_12[90], gate_12[91], gate_12[92], gate_12[93], gate_12[94], gate_12[95], gate_12[96], gate_12[97], gate_12[98], gate_12[99], gate_12[100], gate_12[101], gate_12[102], gate_12[103], gate_12[104], gate_12[105], gate_12[106], gate_12[107], gate_12[108], gate_12[109], gate_12[110], gate_12[111], gate_12[112], gate_12[113], gate_12[114], gate_12[115], gate_12[116], gate_12[117], gate_12[118], gate_12[119], gate_12[120], gate_12[121], gate_12[122], gate_12[123], gate_12[124], gate_12[125], gate_12[126], gate_12[127], gate_12[128], gate_12[129], gate_12[130], gate_12[131], gate_12[132], gate_12[133], gate_12[134], gate_12[135], gate_12[136], gate_12[137], gate_12[138], gate_12[139], gate_12[140], gate_12[141], gate_12[142], gate_12[143], gate_12[144], gate_12[145], gate_12[146], gate_12[147], gate_12[148], gate_12[149], gate_12[150], gate_12[151], gate_12[152], gate_12[153], gate_12[154], gate_12[155], gate_12[156], gate_12[157], gate_12[158], gate_12[159], gate_12[160], gate_12[161], gate_12[162], gate_12[163], gate_12[164], gate_12[165], gate_12[166], gate_12[167], gate_12[168], gate_12[169], gate_12[170], gate_12[171], gate_12[172], gate_12[173], gate_12[174], gate_12[175], gate_12[176], gate_12[177], gate_12[178], gate_12[179], gate_12[180], gate_12[181], gate_12[182], gate_12[183], gate_12[184], gate_12[185], gate_12[186], gate_12[187], gate_12[188], gate_12[189], gate_12[190], gate_12[191], gate_12[192], gate_12[193], gate_12[194], gate_12[195], gate_12[196], gate_12[197], gate_12[198], gate_12[199], gate_12[200], gate_12[201], gate_12[202], gate_12[203], gate_12[204], gate_12[205], gate_12[206], gate_12[207], gate_12[208], gate_12[209], gate_12[210], gate_12[211], gate_12[212], gate_12[213], gate_12[214], gate_12[215], gate_12[216], gate_12[217], gate_12[218], gate_12[219], gate_12[220], gate_12[221], gate_12[222], gate_12[223], gate_12[224], gate_12[225], gate_12[226], gate_12[227], gate_12[228], gate_12[229], gate_12[230], gate_12[231], gate_12[232], gate_12[233], gate_12[234], gate_12[235], gate_12[236], gate_12[237], gate_12[238], gate_12[239], gate_12[240], gate_12[241], gate_12[242], gate_12[243], gate_12[244], gate_12[245], gate_12[246], gate_12[247], gate_12[248], gate_12[249], gate_12[250], gate_12[251], gate_12[252], gate_12[253]] gate_13 ∧
    Gates.eq (20:F) gate_13 ∧
    SliceGadget_3_3 Path Path fun _ =>
    ∃_ignored_, _ignored_ = Gates.mul Path[0] Path[0] ∧
    SliceGadget_2_2 Tree Tree fun _ =>
    Gates.eq (20:F) In ∧
    True

end CircuitWithParameter