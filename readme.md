# `gnark-lean-extractor` library

This is a transpiler from `Go` to `Lean` for arithmetic circuits. You can design your circuit in `Go` and export it to `Lean`.
The benefit of this library is the ability to prototype circuits in a high level language and perform formal verification using `Lean`.

## Example
Here is how a simple circuit is designed using the `gnark-lean-extractor` library:

```go
type DummyCircuit struct {
    In_1 frontend.Variable
    In_2 frontend.Variable
    Out  frontend.Variable
}

func (circuit *DummyCircuit) AbsDefine(api abstractor.API) error {
    sum := api.Add(circuit.In_1, circuit.In_2)
    api.AssertIsEqual(sum, circuit.Out)
    return nil
}
```

Here is how it looks like exported for `Lean`:

```lean
namespace DummyCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order

def circuit (In_1: F) (In_2: F) (Out: F): Prop :=
    ∃gate_0, gate_0 = Gates.add In_1 In_2 ∧
    Gates.eq gate_0 Out ∧
    True

end DummyCircuit
```

Further examples are available in `extractor/extractor_test.go` with various levels of complexity.

## How to use
The circuit API is based on the `consensys/gnark` library with the addition of Gadgets: this makes for easy integration of existing circuits. 
To integrate your own circuit, implement the methods `AbsDefine` and `Define` for `MyCircuit` struct. Choose a circuit curve, then call the extractor with the function `CircuitToLean`:

```go
assignment := MyCircuit{}
out, err := CircuitToLean(&assignment, ecc.BN254)
if err != nil {
    log.Fatal(err)
}
fmt.Println(out)
```

The curves supported match the curves present in the library `consensys/gnark`.

`CircuitToLean` returns a string which contains the circuit in a format readable by `Lean`. The `Lean` code depends on the library `proven-zk` for the representation of Gates, Vectors and other useful circuit verification utilities.

## Notes
If using Powershell, change font to `NSimSun` for correct view of all characters:
[check this answer](https://stackoverflow.com/a/48029600)