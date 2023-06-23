# `gnark-extractor` library

## How to use
Implement the methods `AbsDefine` and `Define` for `MyCircuit`. Choose a curve to test the circuit on, then call the Lean extractor the following way:
```go
assignment := MyCircuit{}
class, _ := CircuitInit(assignment)
assignment = class.(MyCircuit)
err := CircuitToLean(&assignment, ecc.ID)
if err != nil {
    fmt.Println("CircuitToLean error!")
    fmt.Println(err.Error())
}
```
The curves supported match the curves present in the library `consensys/gnark`.

`CircuitToLean` prints in the `stdout` the circuit to be imported in Lean4 for verification. The Lean code depends on library `proven-zk` for the representation of Gates.

## Windows
If using Powershell, change font to `NSimSun` for correct views of all characters (`https://stackoverflow.com/a/48029600`)