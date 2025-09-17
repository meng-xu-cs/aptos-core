# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

move-fuzz is a coverage-guided fuzzer for Move smart contracts within the Aptos monorepo. It automatically generates Move test scripts targeting `public` and `entry` functions, then executes them against a local Aptos VM with mutated inputs to discover bugs. The fuzzer is integrated into the `aptos` CLI binary as `aptos move fuzz`.

## Essential Commands

### Building

The fuzzer is a library crate consumed by the `aptos` CLI binary:
```bash
cargo build -p move-fuzz              # Build just the fuzzer library
cargo build -p aptos                   # Build the full CLI (required to run the fuzzer)
cargo check -p move-fuzz               # Quick compile check
```

### Testing
```bash
cargo test -p move-fuzz                # Run all tests
cargo test -p move-fuzz -- <test_name> # Run a specific test
```

### Linting
```bash
# From the repo root:
cargo xclippy -p move-fuzz            # Clippy
cargo +nightly fmt -- --check          # Format check
```

### Running the Fuzzer
```bash
aptos move fuzz <PATH> list            # List discovered Move packages
aptos move fuzz <PATH> build           # Build all relevant packages
aptos move fuzz <PATH> test            # Run Move unit tests
aptos move fuzz <PATH> exec            # Execute transactions on local testnet
aptos move fuzz <PATH> auto            # Full fuzzing pipeline
```

The `auto` command is the main entrypoint: it builds packages, analyzes types/functions, generates test scripts, and runs the fuzzing loop. Example target: `aptos-move/move-examples/defi`.

Key flags: `--language-version` (default V2_1), `--in-place` (modify workspace directly vs temp dir), `--seed`, `--max-trace-depth`, `--num-user-accounts`.

## Architecture

### Execution Flow

```
CLI (cli.rs) → deps::resolve() → package::build() → Model::new/populate() (prep/)
  → Generate scripts to autogen/sources/ → fuzzer::entrypoint()
    → TracingExecutor (VM) + OneshotFuzzer (per script) → infinite mutation loop
```

### Module Organization

**Core entry & config:**
- `cli.rs` — CLI commands (list/build/test/exec/auto) and the `run_on()` entrypoint
- `fuzzer.rs` — Fuzzing orchestration: script generation, execution loop
- `language.rs` — Move language version settings (V1 through V2.5) and bytecode/optimization levels
- `common.rs` — Core types: `Account`, `TxnArgType`, `TxnArg`, `ExecStatus`

**Package resolution:**
- `deps.rs` — Discovers `Move.toml` files, resolves dependencies topologically, manages named addresses, classifies packages as Primary/Dependency/Framework
- `package.rs` — Compilation and unit test execution for individual packages

**Fuzzing preparation (`prep/`)** — see [Prep Pipeline](#prep-pipeline-in-detail) below

**Execution (`executor/`):**
- `tracing.rs` — `TracingExecutor`: wraps `FakeExecutor` (Aptos VM), manages accounts, gas, and module deployment
- `oneshot.rs` — `OneshotFuzzer`: per-script fuzzer with corpus management and mutation-driven execution

**Mutation (`mutate/`):**
- `mutator.rs` — Value generation and mutation strategies (integers, vectors, addresses) with configurable probabilities

**Network simulation:**
- `simulator.rs` — Local testnet with account/module management and transaction execution
- `testnet.rs` — JSON runbook execution and testnet provisioning

**Utilities:**
- `subexec.rs` — Subprocess execution wrapper
- `utils.rs` — Logging helpers

### Key Design Patterns

- Packages are resolved in topological dependency order; this ordering is preserved throughout the pipeline
- The fuzzer creates an `autogen/` package directory with generated Move scripts that depend on all analyzed packages
- `TracingExecutor` uses `aptos-language-e2e-tests::FakeExecutor` for high-fidelity VM execution without a real network
- Account addresses are auto-assigned during dependency resolution; resource accounts are derived from base addresses with seeds
- The `auto` command overrides `--include-framework` and `--include-deps` to true since the fuzzer needs visibility into all packages

### Test Data

- `tests/demo/` — Example Move package for basic fuzzer testing
- `tests/prep/` — Move files exercising type analysis and function signature patterns

## Prep Pipeline in Detail

The `prep/` directory implements the core analysis that transforms compiled Move bytecode into executable fuzz scripts. The pipeline has four stages: bytecode analysis, type-level reasoning, flow graph construction, and script codegen.

### Stage 1: Bytecode Analysis (`ident.rs`, `datatype.rs`, `function.rs`)

**Identifiers** (`ident.rs`): Three types that wrap Move binary format handles into addressable keys used throughout the pipeline:
- `ModuleIdent` — address + module name
- `DatatypeIdent` — module + struct/enum name
- `FunctionIdent` — module + function name

All are constructed from `BinaryIndexedView` handles (the compiled bytecode representation).

**Datatype Registry** (`datatype.rs`): Two-pass analysis over each `CompiledModule`:
- Pass 1: Registers `DatatypeDecl` — generics (with ability constraints and phantom markers), declared abilities, and package kind (Primary/Dependency/Framework)
- Pass 2: Fills `DatatypeContent` — either `Fields(Vec<TypeTag>)` for structs or `Variants(BTreeMap<String, Vec<TypeTag>>)` for enums

Three intrinsic types (`BitVector`, `String`, `Object<T>`) are recognized by address/module/name and get special handling rather than being registered as user datatypes.

Key methods:
- `convert_signature_token()` — Converts bytecode `SignatureToken` → `TypeRef` (the fuzzer's type representation). Recognizes intrinsics and handles `Object<T>` specially (splits into `ObjectKnown`/`ObjectParam`)
- `instantiate_type_tag()` — Substitutes type parameters: `TypeTag` + type args → `TypeBase` (concrete type with abilities)
- `derive_actual_ability()` — Computes effective abilities of a generic struct by intersecting non-phantom type argument abilities with declared abilities

**Function Registry** (`function.rs`): Scans modules for `Visibility::Public` functions only. Records `FunctionDecl` containing the identifier, generic ability constraints, parameter types (as `TypeRef`), and return types.

### Stage 2: Type System (`typing.rs`)

The type system uses multiple representation levels for types at different stages of analysis:

**Uninstantiated types (from bytecode):**
- `TypeTag` — Types with unresolved generics (`Param(usize)` for type parameters). Includes special variants `ObjectKnown`/`ObjectParam` for `Object<T>`
- `TypeRef` — `TypeTag` wrapped with reference mode: `Base`, `ImmRef`, or `MutRef`

**Instantiated types (with concrete abilities):**
- `TypeBase` — Concrete types carrying ability information. Like `TypeTag` but `Param` includes its `AbilitySet`, and `Datatype` carries computed abilities
- `TypeItem` — `TypeBase` wrapped with reference mode

**Classification for script generation:**
- `SimpleType` — Types the fuzzer can construct trivially as inputs (primitives, strings, addresses, signers, objects, vectors of simple types)
- `ComplexType` — Types requiring function calls to construct (user-defined structs, type parameters, vectors of complex types)
- `TypeMode::convert()` — Classifies a `TypeBase` as Simple or Complex. This classification drives the core decision in script generation: simple types become fuzzer parameters, complex types require flow graph resolution

**Type unification (two mechanisms):**
- `TypeSubstitution` — One-directional: unifies `TypeTag` → `TypeBase`. Used in `probe_external()` when matching a function's return type signature against a needed concrete type. Assigns type parameters and checks ability constraints
- `TypeUnification` — Bidirectional: unifies `TypeBase` ↔ `TypeBase` with equivalence groups. Used in `probe_internal()` and `probe_copyable()` when matching two concrete types that may share unresolved generics. Supports cyclic detection via `TIError::CyclicUnification`

### Stage 3: Flow Graph Construction (`graph.rs`)

The flow graph is a DAG (`petgraph::DiGraph`) that encodes how to construct all arguments needed to call a target function. This is the most algorithmically complex part of the fuzzer.

**Graph structure:**
- `FlowGraphNode::Function(FunctionInst)` — A function call with concrete type arguments
- `FlowGraphNode::Datatype(DatatypeItem)` — A value of complex type flowing between functions
- `FlowGraphEdge::Use(param_idx)` — Datatype node feeds into function's parameter at index
- `FlowGraphEdge::Def(ret_idx)` — Function's return value at index produces a datatype
- Transformation edges: `Copy`, `Deref`, `Freeze`, `ImmBorrow`, `MutBorrow`, `VectorToElement`, `ElementToVector`

**`GraphBuilder` — recursive backtracking search:**

Entry: `process(decl, type_args)` creates an empty flow graph and calls `add_call()`.

`add_call()` adds a function node, instantiates its parameter types, and for each complex-typed parameter, calls `add_arg()`. Enforces `max_trace_depth` (how deep the call chain can be) and `max_call_repetition` (how many times the same function instantiation can appear).

`add_arg()` creates a datatype node with a `Use` edge to the function, then delegates to `plan_for_datatype()`.

`plan_for_datatype()` is the core recursive solver. For each complex datatype needed, it explores multiple strategies in parallel (each producing candidate flow graphs):

1. **`probe_internal()`** — Checks if an existing function node in the graph has an unused return value of the right type. Uses `TypeUnification` to match types. Prevents cycles via `is_cyclic_directed()`
2. **`probe_external()`** — Searches the entire function registry for functions that return the needed type. Uses `TypeSubstitution` to match return type signatures. For unresolved generics, enumerates all valid ability set combinations via `ability_set_candidates()`. Recursively calls `add_call()` for each candidate
3. **`probe_copyable()`** — If the type has `copy` ability, checks if an existing same-typed datatype node can be copied (prevents copy chains)
4. **Structural transformations** — Tries to obtain the needed type through: dereferencing (`&T`/`&mut T` → `T` if copyable), freezing (`&mut T` → `&T`), borrowing (`T` → `&T`/`&mut T`), vector operations (`vector<T>` ↔ `T`)

Each strategy produces zero or more candidate `FlowGraph` instances; the builder accumulates all valid alternatives.

**Feasibility check** (`is_feasible()`): A graph is feasible if: (1) it is acyclic, (2) at most one `signer` parameter exists, and (3) all non-droppable return values are consumed by downstream nodes.

**`FlowGraph::compact_generics()`**: After construction, renumbers type parameters to a contiguous 0-based sequence (removing gaps from unused generics).

### Stage 4: Script Code Generation (`canvas.rs`, `model.rs`)

**`Model::populate()`** (`model.rs`) drives the pipeline:
1. For each primary function declaration, enumerates all valid generic instantiation candidates (cartesian product of `ability_set_candidates` per type parameter)
2. Calls `GraphBuilder::process()` to generate flow graphs
3. Filters by `is_feasible()`
4. Compacts generics
5. Builds a `DriverCanvas` from each graph
6. Generates `.move` script files to the autogen output directory

**`DriverCanvas::build()`** (`canvas.rs`) converts a flow graph DAG into an imperative script:
- Topological-sorts the graph nodes
- For each **datatype node**: emits a transformation statement (Copy, Deref, Freeze, ImmBorrow, MutBorrow, VectorToElement, ElementToVector) based on the outgoing edge type
- For each **function node**: collects incoming `Use` edges as arguments, creates a `Call` statement. Simple-typed parameters become `BasicInput` fuzzer inputs. Complex-typed parameters use values from the flow graph
- Tracks variables as `DriverVariable::Param(i)` (fuzzer inputs) or `DriverVariable::Local(i)` (intermediate values)

**`generate_script()`** renders the canvas to Move source: writes `fuzz_script_N.move` containing a `script` block with the driver function. Returns a `ScriptSignature` (name, generics, parameters) consumed by the execution engine to know what inputs to fuzz.
