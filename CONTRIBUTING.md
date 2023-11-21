# Contributing

This document exists as a brief introduction for how you can contribute to this
repository. It includes a guide to
[the structure of the repository](#repository-structure),
[demo](#demo) of a circuit with full formal verification,
[testing](#testing) and [getting your code on `main`](#getting-your-code-on-main).

If you are new to Go, there is a [guide](#new-to-go) to getting started with the
language that provides some basic resources for getting started.

> ## Font Display in Powershell
>
> If using Powershell, change font to `NSimSun` to be able to see all characters
> properly. This is taken from
> [this stackoverflow answer](https://stackoverflow.com/a/48029600).

## Repository Structure

This repository consists of a single package called [`parser`](./parser):
it is responsible for implementing the `frontend.API` interface from 
[gnark](https://github.com/ConsenSys/gnark) and call [lean-circuit-compiler](https://github.com/reilabs/lean-circuit-compiler)
with relevant structures to generate the Lean code for formal verification of the circuit.

This repository has a dedicated branch for each version of [gnark](https://github.com/ConsenSys/gnark)
in order to ensure continuous compatibility of your circuits.

## Demo

You can build and see the project in action as follows.

1. Clone the repository into a location of your choice.

```sh
git clone https://github.com/reilabs/gnark-lean-demo
```

2. Build the go circuit project using `go` (meaning that you will need to have
   that toolchain set up).

```sh
cd gnark-lean-demo
go mod download
go build -o gnark-lean-demo -v ./...
./gnark-lean-demo extract-circuit --out=lean-circuit/LeanCircuit.lean
```

The Lean code will be printed in the file `lean-circuit/LeanCircuit.lean`

## Testing

You can test the parser with pre-defined circuits included in package [`parser_test`](./parser/package).

1. Clone the repository into a location of your choice.

```sh
git clone https://github.com/reilabs/gnark-lean-extractor
```

2. Build the go circuit project using `go` (meaning that you will need to have
   that toolchain set up).

```sh
cd gnark-lean-extractor
go test -v ./...
```

## Getting Your Code on `main`

This repository works on a fork and
[pull request](https://github.com/reilabs/gnark-lean-demo/pulls) workflow, with
code review and CI as an integral part of the process. This works as follows:

1. If necessary, you fork the repository, but if you have access to do so please
   create a branch.
2. You make your changes on that branch.
3. Pull request that branch against main.
4. The pull request will be reviewed and CI will be run on it.
5. Once the reviewer(s) have accepted the code and CI has passed, the code will
   be merged to `main`.

## New to Go?

If you are new to working with [Go](https://go.dev), a great place to start is
the official set of [tutorials](https://go.dev/learn/). They explain how to
[install](https://go.dev/doc/install) and set the language up, as well as an
[interactive tour](https://go.dev/tour/welcome/1) of how to use the language.

We recommend being familiar with the language and the `go` command-line
interface to the build system and compiler before interacting with the Go
portion of this repository.

