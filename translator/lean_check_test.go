package translator_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// leanStub swaps the Mathlib-dependent part of the prelude (ZMod and its
// field structure) for core-only stand-ins so the generated file can be
// type-checked with a bare `lean` binary. The stubs deliberately have wrong
// arithmetic semantics — this checks that everything else (the Circuit
// monad, do-notation, goRange loops, Int64 usage, list indexing) elaborates.
func leanStub(out string) string {
	out = strings.Replace(out, "import Mathlib.Data.ZMod.Basic\n\n", "", 1)
	out = strings.Replace(out, "def Order : ℕ", "def Order : Nat", 1)
	out = strings.Replace(out,
		`abbrev F := ZMod Order
variable [Fact (Nat.Prime Order)]
`,
		`abbrev F := Int
class Inv (α : Type) where inv : α → α
postfix:max "⁻¹" => Inv.inv
instance : Inv F := ⟨fun x => x⟩
def _root_.Int.val (a : Int) : Nat := a.toNat
`, 1)
	return out
}

func TestLeanTypeCheck(t *testing.T) {
	leanBin, err := exec.LookPath("lean")
	if err != nil {
		t.Skip("lean not on PATH; skipping type check of golden files")
	}
	goldens, err := filepath.Glob(filepath.Join("testdata", "*", "expected.lean"))
	if err != nil || len(goldens) == 0 {
		t.Fatalf("no golden files found: %v", err)
	}
	for _, golden := range goldens {
		golden := golden
		t.Run(filepath.Base(filepath.Dir(golden)), func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			stub := leanStub(string(data))
			if stub == string(data) {
				t.Fatal("stub substitution did not apply")
			}
			tmp := filepath.Join(t.TempDir(), "Check.lean")
			if err := os.WriteFile(tmp, []byte(stub), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command(leanBin, tmp).CombinedOutput()
			if err != nil {
				t.Errorf("lean rejected %s:\n%s", golden, out)
			}
		})
	}
}
