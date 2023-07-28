# `gnark-lean-extractor` library

## How to use
Implement the methods `AbsDefine` and `Define` for `MyCircuit` struct. Choose a curve to test the circuit on, then call the Lean extractor the following way:
```go
assignment := MyCircuit{}
out, err := CircuitToLean(&assignment, ecc.BN254)
if err != nil {
    log.Fatal(err)
}
fmt.Println(out)
```
The curves supported match the curves present in the library `consensys/gnark`.

`CircuitToLean` prints in the `stdout` the circuit to be imported in Lean4 for verification. The Lean code depends on library `proven-zk` for the representation of Gates.

## Windows
If using Powershell, change font to `NSimSun` for correct view of all characters:
[check this answer](https://stackoverflow.com/a/48029600)