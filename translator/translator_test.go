package translator_test

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/reilabs/gnark-lean-extractor/v3/translator"
)

var update = flag.Bool("update", false, "update golden files")

func checkGolden(t *testing.T, goldenPath string, out string) {
	t.Helper()
	if *update {
		if err := os.WriteFile(goldenPath, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("missing golden file (run with -update): %v", err)
	}
	if string(want) != out {
		t.Errorf("output differs from %s.\n--- got ---\n%s", goldenPath, out)
	}
}

func TestMerkleChain(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:       "testdata/simple",
		Circuit:   "MerkleChain",
		Namespace: "MerkleChain",
		Field:     ecc.BN254,
		Blackboxes: map[string]string{
			"github.com/reilabs/gnark-lean-extractor/v3/translator/testdata/simple.mimc": "MiMC",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "simple", "expected.lean"), out)
}

// TestRejections checks that circuits whose Go semantics the functional
// translation cannot reproduce fail loudly instead of translating wrong.
func TestRejections(t *testing.T) {
	cases := []struct {
		circuit string
		wantErr string
	}{
		{"LoopBound", "loop bound"},
		{"RangeWrite", "ranged over"},
		{"Alias", "aliases a slice"},
		{"DirtyArg", "writes the elements"},
		{"ReturnAlias", "result of id may alias xs"},
		{"SameArg", "more than once"},
		{"MapField", "unsupported type"},
	}
	for _, c := range cases {
		c := c
		t.Run(c.circuit, func(t *testing.T) {
			_, err := translator.Translate(translator.Config{
				Dir:     "testdata/bad",
				Circuit: c.circuit,
				Field:   ecc.BN254,
			})
			if err == nil {
				t.Fatalf("expected translation of %s to fail", c.circuit)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("error for %s should mention %q, got: %v", c.circuit, c.wantErr, err)
			}
		})
	}
}

func TestPoseidonMerkle(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/poseidon",
		Circuit: "MerkleRecover",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "poseidon", "expected.lean"), out)
}

func TestPadded(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/padded",
		Circuit: "Padded",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "padded", "expected.lean"), out)
}

func TestBitsCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/bits",
		Circuit: "BitsCircuit",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "bits", "expected.lean"), out)
}

func TestOpaqueCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/opaque",
		Circuit: "Opaque",
		Field:   ecc.BN254,
		Blackboxes: map[string]string{
			"github.com/reilabs/gnark-lean-extractor/v3/translator/testdata/opaque.keyDigest": "keyDigest",
		},
		OpaqueTypes: map[string]string{
			"github.com/reilabs/gnark-lean-extractor/v3/translator/testdata/opaque/inner.Wrap": "PubKey",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "opaque", "expected.lean"), out)
}

func TestGadgetCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/gadget",
		Circuit: "Gadget",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "gadget", "expected.lean"), out)
}

func TestPtrsCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/ptrs",
		Circuit: "Ptrs",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "ptrs", "expected.lean"), out)
}

func TestSliceExprCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/sliceexpr",
		Circuit: "SliceExpr",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "sliceexpr", "expected.lean"), out)
}

func TestCopyBuiltinCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/copybuiltin",
		Circuit: "CopyBuiltin",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "copybuiltin", "expected.lean"), out)
}

func TestBytesCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/bytes",
		Circuit: "Bytes",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "bytes", "expected.lean"), out)
}

func TestNestedCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/nested",
		Circuit: "Nested",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "nested", "expected.lean"), out)
}

func TestErrretCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/errret",
		Circuit: "Errret",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "errret", "expected.lean"), out)
}

// TestBigIntCircuit covers the math/big peepholes and Int64 shift support.
func TestBigIntCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/bigint",
		Circuit: "BigInt",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "bigint", "expected.lean"), out)
}

// TestCompoundLoopCircuit covers `for i := lo; i < hi && <residual>; i++`
// — the compound condition is lowered to `.takeWhile` on the range list.
func TestCompoundLoopCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/compound",
		Circuit: "Compound",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "compound", "expected.lean"), out)
}

// TestStrideCircuit covers `for i := lo; i < hi; i += k` loops with both a
// compile-time-constant stride and a runtime stride.
func TestStrideCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/stride",
		Circuit: "Stride",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "stride", "expected.lean"), out)
}

// TestPanicCircuit covers the two panic patterns: `if err != nil { panic(err) }`
// gets dropped as Go-side plumbing, and a bare precondition panic emits
// `Circuit.panic` under an if.
func TestPanicCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/panic",
		Circuit: "Panic",
		Field:   ecc.BN254,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "panic", "expected.lean"), out)
}

// TestMultiPackageCircuit exercises Config.WalkPackages: the circuit calls
// into a foreign subpackage whose function, struct + method, and gadget
// (via abstractor.Call) are all translated rather than blackboxed.
func TestMultiPackageCircuit(t *testing.T) {
	out, err := translator.Translate(translator.Config{
		Dir:     "testdata/multi",
		Circuit: "Multi",
		Field:   ecc.BN254,
		WalkPackages: []string{
			"github.com/reilabs/gnark-lean-extractor/v3/translator/testdata/multi/helpers",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, filepath.Join("testdata", "multi", "expected.lean"), out)
}

// TestMultiPackageRejection confirms that without WalkPackages the foreign
// helper call is still rejected with the standard "register it as a
// blackbox" error — the boundary hasn't been silently widened.
func TestMultiPackageRejection(t *testing.T) {
	_, err := translator.Translate(translator.Config{
		Dir:     "testdata/multi",
		Circuit: "Multi",
		Field:   ecc.BN254,
	})
	if err == nil {
		t.Fatal("expected translation to fail without WalkPackages")
	}
	if !strings.Contains(err.Error(), "register it as a blackbox") {
		t.Errorf("expected foreign-call rejection, got: %v", err)
	}
}

// TestMultiPackageBadPrefix verifies that a WalkPackages entry that doesn't
// match any actually-imported package produces a clear error rather than
// silently doing nothing.
func TestMultiPackageBadPrefix(t *testing.T) {
	_, err := translator.Translate(translator.Config{
		Dir:          "testdata/multi",
		Circuit:      "Multi",
		Field:        ecc.BN254,
		WalkPackages: []string{"example.com/does-not-exist"},
	})
	if err == nil {
		t.Fatal("expected translation to fail for a non-matching prefix")
	}
	if !strings.Contains(err.Error(), "did not match") {
		t.Errorf("expected unmatched-prefix error, got: %v", err)
	}
}
