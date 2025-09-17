# Move Fuzzer

This directory contains the source code of a coverage-guided fuzzer for Move smart contracts.

## File Layout

```txt
# Command-line interface (starting point of code logic)
- cli.rs

# Configurations and useful type definitions
- common.rs
- language.rs

# Package (including dependency) resolution, build, and testing
- deps.rs
- package.rs

# Local testnet (localnet) simulation
- simulator.rs
- testnet.rs

# Fuzzing core
- fuzzer.rs

- prep/
  # Fuzzing preparation and test script generation
  - ident.rs
  - datatype.rs
  - function.rs
  - model.rs
  - canvas.rs
  - driver.rs

- base/ (WIP)
  # Baseline fuzzer (oneshot execution of a single entry script)
  - executor.rs
  - mutate.rs
  - oneshot.rs

# Utilities not directly related to fuzzing
- utils.rs
- subexec.rs
```

## User Guide

### Build the fuzzer

The fuzzer is integrated into the `aptos` binary in the monorepo. To build it, simply build the `aptos` package via:
```bash
cargo build -p aptos
```

For more details, follow the [Building Aptos From Source](https://aptos.dev/network/nodes/building-from-source) documentation.

### View the help message

The command-line interface for using the fuzzer is
```bash
aptos move fuzz [OPTIONS] <PATH> <COMMAND>
```

### Run the fuzzer

The core fuzzing logic is encapsulated under
```bash
aptos move fuzz [OPTIONS] <PATH> auto
```

As the fuzzer is still under development, the behavior of this command will change frequently.

As of Oct 16, 2025, this command will simply build the Move package and all its dependencies, analyze their types and functions, and prepare for script generation for all `public` and `entry` functions in the *primary* Move package, (i.e., the package at `<PATH>`). We will add script compilation and oneshot execution logic soon.

### Periphery commands

While not core features, the fuzzer has actually good support on esolution of a Move package, its dependencies, and most importantly, **auto address assignment** during package build and publishing. These functionalities are needed for fuzzing as the fuzzing will be executed over an actual local testnet for high-fidelity storage management and stateful simulation.

#### List all relevant Move packages

```bash
aptos move fuzz [OPTIONS] <PATH> list
```

#### Build all relevant Move packages

```bash
aptos move fuzz [OPTIONS] <PATH> build
```

#### Run Move unit tests in all relevant Move packages

```bash
aptos move fuzz [OPTIONS] <PATH> test
```

#### Publish Move packages on a fresh localnet and execute multiple transactions

```bash
aptos move fuzz [OPTIONS] <PATH> exec
```

### Examples

You can try the fuzzers under a well-formed Move project, such as the DeFi example under `aptos-core/aptos-move/move-examples/defi`.

