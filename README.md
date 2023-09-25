<a href="https://reilabs.io">
<picture>
  <source width="150" media="(prefers-color-scheme: dark)" srcset="https://github.com/reilabs/gnark-lean-extractor/assets/35899/c04bdb7f-4c31-4264-acb6-a96f32c6cc29">
  <source width="150" media="(prefers-color-scheme: light)" srcset="https://github.com/reilabs/gnark-lean-extractor/assets/35899/fc11280b-e3e5-4a6f-83da-788884083c36">
  <img width="150" src="https://github.com/reilabs/gnark-lean-extractor/assets/35899/fc11280b-e3e5-4a6f-83da-788884083c36">
</picture>
</a>

# Gnark Lean Extractor

This repository contains a Go library that transpiles
[zero-knowledge](https://en.wikipedia.org/wiki/Zero-knowledge_proof) (ZK)
circuits from [Go](https://go.dev) to [Lean](https://leanprover.github.io). In
particular, it deals with circuits constructed as part of the
[gnark](https://github.com/ConsenSys/gnark) proof system.

This makes it possible to take existing gnark circuits and export them to Lean
for later formal verification.

For an overview of how to use this library, see both the [example](#example) and
[usage guide](#how-to-use-the-library) below. If you are interested in
contributing, or are new to Go, please see our
[contributing guidelines](./CONTRIBUTING.md) for more information.

## Example

The following is a brief example of how to design a simple gnark circuit in
conjunction with the extractor library.

```go
type MyCircuit struct {
    In_1 frontend.Variable
    In_2 frontend.Variable
    Out  frontend.Variable
}

func (circuit *MyCircuit) Define(api abstractor.API) error {
    sum := api.Add(circuit.In_1, circuit.In_2)
    api.AssertIsEqual(sum, circuit.Out)
    return nil
}

func (circuit MyCircuit) Define(api frontend.API) error {
    return abstractor.Concretize(api, &circuit)
}
```

Once you export this to Lean, you get a definition as follows:

```lean
namespace MyCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order

def circuit (In_1: F) (In_2: F) (Out: F): Prop :=
    ∃gate_0, gate_0 = Gates.add In_1 In_2 ∧
    Gates.eq gate_0 Out ∧
    True

end MyCircuit
```

Further examples of this process with various levels of complexity can be seen
in [`extractor_test.go`](./extractor/extractor_test.go). You can also peruse the
[Gnark Extractor Demo](https://github.com/reilabs/gnark-lean-demo), which uses
this library alongside an implementation of
[Semaphore](https://semaphore.appliedzkp.org).

## How to Use the Library

If you are familiar with the [gnark library](https://github.com/consensys/gnark)
(as you will need to be to write ZK circuits), the circuit API in this library
should be familiar.

Based directly on the gnark interface, this library adds "gadgets" and hence
makes it easy to integrate with existing circuits. To do so, you have to
implement the `AbsDefine` method for the struct that represents your circuit
(`MyCircuit` in the example below). You can use the `abstractor.Concretize`
function to automatically derive an implementation of `Define` for further use
with gnark.

After doing that, you choose a circuit curve from those present in the
aforementioned gnark library, and then call the extractor function
`CircuitToLean`.

```go
circuit := MyCircuit{}
out, err := CircuitToLean(&circuit, ecc.BN254)
if err != nil {
    log.Fatal(err)
}
fmt.Println(out)
```

`CircuitToLean` returns a string which contains the circuit output in a format
that can be read by the Lean language. The lean code depends on Reilabs'
[ProvenZK](https://github.com/reilabs/proven-zk) library in order to represent
gates and other components of the circuit. In doing so, it makes the extracted
circuit formally verifiable.

