// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    executor::tracing::{ResourceWrite, TracingExecutor},
    mutate::mutator::{Mutator, TypePool},
    prep::canvas::{BasicInput, ScriptSignature},
};
use anyhow::Result;
use aptos_types::transaction::{
    ExecutionStatus, Script, TransactionArgument, TransactionPayload, TransactionStatus,
};
use move_core_types::{
    language_storage::TypeTag as VmTypeTag,
    value::MoveValue,
    vm_status::{AbortLocation, StatusCode, VMStatus},
};
use move_coverage::coverage_map::{CoverageMap, ExecCoverageMap, ModuleCoverageMap};
use move_vm_runtime::tracing::{clear_tracing_buffer, flush_tracing_buffer};
use std::{fmt::Display, path::PathBuf, time::Instant};

/// Status of one execution
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum ExecStatus {
    Success,
    AbortIntrinsic {
        status_code: StatusCode,
        sub_status: Option<u64>,
        location: AbortLocation,
        function: u16,
        instruction: u16,
    },
    AbortDeclared {
        abort_code: u64,
        location: AbortLocation,
    },
    ErrorKept {
        status_code: StatusCode,
        sub_status: Option<u64>,
    },
    ErrorDiscard {
        status_code: StatusCode,
        sub_status: Option<u64>,
    },
    OutOfGas,
}

impl Into<ExecStatus> for (VMStatus, TransactionStatus) {
    fn into(self) -> ExecStatus {
        match self {
            (VMStatus::Executed, TransactionStatus::Keep(ExecutionStatus::Success)) => {
                ExecStatus::Success
            },
            (
                VMStatus::Error {
                    status_code,
                    sub_status,
                    message: _,
                },
                TransactionStatus::Discard(code),
            ) => {
                assert_eq!(status_code, code);
                ExecStatus::ErrorDiscard {
                    status_code,
                    sub_status,
                }
            },
            (
                VMStatus::Error {
                    status_code,
                    sub_status,
                    message: _,
                },
                TransactionStatus::Keep(ExecutionStatus::OutOfGas),
            ) => {
                assert_eq!(status_code, StatusCode::OUT_OF_GAS);
                assert!(sub_status.is_none());
                ExecStatus::OutOfGas
            },
            (
                VMStatus::Error {
                    status_code,
                    sub_status,
                    message: _,
                },
                TransactionStatus::Keep(ExecutionStatus::MiscellaneousError(Some(code))),
            ) => {
                assert_eq!(status_code, code);
                ExecStatus::ErrorKept {
                    status_code,
                    sub_status,
                }
            },
            (
                VMStatus::MoveAbort {
                    location,
                    code: abort_code,
                    message: _,
                },
                TransactionStatus::Keep(ExecutionStatus::MoveAbort {
                    location: loc,
                    code,
                    info: _,
                }),
            ) => {
                assert_eq!(location, loc);
                assert_eq!(abort_code, code);
                ExecStatus::AbortDeclared {
                    abort_code,
                    location,
                }
            },
            (
                VMStatus::ExecutionFailure {
                    status_code,
                    sub_status,
                    location,
                    function,
                    code_offset: instruction,
                    message: _,
                },
                TransactionStatus::Keep(ExecutionStatus::ExecutionFailure {
                    location: loc,
                    function: func,
                    code_offset,
                }),
            ) => {
                assert_eq!(location, loc);
                assert_eq!(function, func);
                assert_eq!(instruction, code_offset);
                ExecStatus::AbortIntrinsic {
                    status_code,
                    sub_status,
                    location,
                    function,
                    instruction,
                }
            },
            (vm_status, txn_status) => {
                panic!("invalid status combination: {vm_status:?} and {txn_status:?}");
            },
        }
    }
}

impl ExecStatus {
    /// Return a short category label for aggregated reporting
    pub fn category(&self) -> &'static str {
        match self {
            ExecStatus::Success => "success",
            ExecStatus::AbortIntrinsic { .. } => "abort",
            ExecStatus::AbortDeclared { .. } => "abort",
            ExecStatus::ErrorKept { .. } => "error",
            ExecStatus::ErrorDiscard { .. } => "discard",
            ExecStatus::OutOfGas => "out-of-gas",
        }
    }
}

impl Display for ExecStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecStatus::Success => write!(f, "success"),
            ExecStatus::AbortIntrinsic {
                status_code,
                sub_status,
                location,
                function,
                instruction,
            } => match sub_status {
                None => write!(
                    f,
                    "abort({status_code:?} @ {location}::{function}::{instruction})"
                ),
                Some(v) => write!(
                    f,
                    "abort({status_code:?}::{v} @ {location}::{function}::{instruction})"
                ),
            },
            ExecStatus::AbortDeclared {
                location,
                abort_code,
            } => write!(f, "abort({abort_code} @ {location})"),
            ExecStatus::ErrorKept {
                status_code,
                sub_status,
            } => match sub_status {
                None => write!(f, "error({status_code:?})"),
                Some(v) => write!(f, "error({status_code:?}::{v})"),
            },
            ExecStatus::ErrorDiscard {
                status_code,
                sub_status,
            } => match sub_status {
                None => write!(f, "discard({status_code:?})"),
                Some(v) => write!(f, "discard({status_code:?}::{v})"),
            },
            ExecStatus::OutOfGas => write!(f, "out-of-gas"),
        }
    }
}

/// A one-shot fuzzer
pub struct OneshotFuzzer {
    script_sig: ScriptSignature,
    script_code: Vec<u8>,
    executor: TracingExecutor,
    mutator: Mutator,
    trace_path: PathBuf,
    coverage: ExecCoverageMap,
    seedpool: Vec<(Vec<VmTypeTag>, Vec<MoveValue>)>,

    // statistics counting
    exec_count: u64,
    last_new_coverage_time: Option<Instant>,
    coverage_at_last_report: usize,
}

impl OneshotFuzzer {
    /// Create a new one-shot fuzzer
    pub fn new(
        executor: TracingExecutor,
        seed: u64,
        script_sig: ScriptSignature,
        script_code: Vec<u8>,
        type_pool: TypePool,
        trace_path: PathBuf,
        dict_string: Vec<String>,
    ) -> Self {
        // prepare the fuzzer
        Self {
            mutator: Mutator::new(
                seed,
                executor.all_addresses_by_kind(),
                type_pool,
                dict_string,
            ),
            executor,
            script_sig,
            script_code,
            trace_path,
            coverage: ExecCoverageMap::new(String::new()),
            seedpool: vec![],
            exec_count: 0,
            last_new_coverage_time: None,
            coverage_at_last_report: 0,
        }
    }

    /// Get the core of the script
    pub fn script_desc(&self) -> String {
        self.script_sig.ident.to_string()
    }

    /// Get the current corpus (seed pool) size
    pub fn corpus_size(&self) -> usize {
        self.seedpool.len()
    }

    /// Get the total number of covered bytecode positions across all modules
    pub fn coverage_count(&self) -> usize {
        self.coverage
            .module_maps
            .values()
            .flat_map(|m| m.function_maps.values())
            .map(|f| f.len())
            .sum()
    }

    /// Get the total number of executions
    pub fn exec_count(&self) -> u64 {
        self.exec_count
    }

    /// Get when coverage was last found
    pub fn last_new_coverage_time(&self) -> Option<Instant> {
        self.last_new_coverage_time
    }

    /// Get the coverage delta since last report and reset the snapshot
    pub fn coverage_delta_since_report(&mut self) -> usize {
        let current = self.coverage_count();
        let delta = current.saturating_sub(self.coverage_at_last_report);
        self.coverage_at_last_report = current;
        delta
    }

    /// Short description: `module::function`
    pub fn script_short_desc(&self) -> String {
        format!(
            "{}::{}",
            self.script_sig.ident.module_name(),
            self.script_sig.ident.function_name()
        )
    }

    /// Execute one entry-point. Returns (status, corpus_size, found_new_coverage, resource_writes).
    /// Resource writes are only returned for successful transactions.
    pub fn run_one(&mut self) -> Result<(ExecStatus, usize, bool, Vec<ResourceWrite>)> {
        // prepare
        let sender = self.mutator.random_signer();

        // the VM automatically injects the signer from the transaction sender,
        // so we only generate/mutate non-signer parameters as script arguments
        let non_signer_params: Vec<_> = self
            .script_sig
            .parameters
            .iter()
            .filter(|ty| !matches!(ty, BasicInput::Signer))
            .collect();

        // generate or mutate type arguments and value arguments
        let (ty_args, args): (Vec<VmTypeTag>, Vec<MoveValue>) =
            match self.mutator.should_mutate(self.seedpool.len()) {
                None => {
                    // generate new type arguments and value arguments
                    let ty_args = self.mutator.random_type_args(&self.script_sig.generics);
                    let args = non_signer_params
                        .iter()
                        .map(|ty| self.mutator.random_value(ty))
                        .collect();
                    (ty_args, args)
                },
                Some(index) => {
                    // mutate existing seed
                    let (seed_ty_args, seed_args) = &self.seedpool[index];
                    assert_eq!(non_signer_params.len(), seed_args.len());

                    let ty_args = if !self.script_sig.generics.is_empty()
                        && self.mutator.should_mutate_type_args()
                    {
                        self.mutator
                            .mutate_type_args(&self.script_sig.generics, seed_ty_args)
                    } else {
                        seed_ty_args.clone()
                    };

                    let args = seed_args
                        .iter()
                        .zip(non_signer_params.iter())
                        .map(|(val, ty)| self.mutator.mutate_value(ty, val))
                        .collect();
                    (ty_args, args)
                },
            };

        let payload = TransactionPayload::Script(Script::new(
            self.script_code.clone(),
            ty_args.clone(),
            args.iter()
                .map(|arg| {
                    TransactionArgument::Serialized(
                        MoveValue::simple_serialize(arg).expect("arguments must serialize"),
                    )
                })
                .collect(),
        ));

        // prologue: reset the VM's trace buffer (truncates and reopens the file)
        clear_tracing_buffer();

        // execute
        let (vm_status, txn_status, resource_writes) =
            self.executor.run_payload_with_sender(sender, payload)?;

        // update object dictionary from write set
        self.mutator.update_object_dict(&resource_writes);

        // epilogue: flush and read coverage
        flush_tracing_buffer();

        // update coverage and seed pool
        self.exec_count += 1;
        let coverage_map = CoverageMap::from_trace_file(&self.trace_path)?;
        let found_new = self.update_coverage(coverage_map);
        if found_new {
            self.last_new_coverage_time = Some(Instant::now());
            self.seedpool.push((ty_args, args));
        }

        // only share resource writes from successful transactions
        let exec_status = (vm_status, txn_status).into();
        let shared_writes = if matches!(exec_status, ExecStatus::Success) {
            resource_writes
        } else {
            vec![]
        };

        // return status
        Ok((exec_status, self.seedpool.len(), found_new, shared_writes))
    }

    /// Absorb shared object discoveries from other fuzzers
    pub fn absorb_shared_object_writes(&mut self, writes: &[ResourceWrite]) {
        self.mutator.update_object_dict(writes);
    }

    /// Update coverage map, return true if new coverage is found
    fn update_coverage(&mut self, new_map: CoverageMap) -> bool {
        let mut found_new = false;
        for new_exec_map in new_map.exec_maps.into_values() {
            for (key, new_module_map) in new_exec_map.module_maps {
                let module_map = self.coverage.module_maps.entry(key).or_insert_with(|| {
                    ModuleCoverageMap::new(new_module_map.module_addr, new_module_map.module_name)
                });
                for (ident, new_func_map) in new_module_map.function_maps {
                    let func_map = module_map.function_maps.entry(ident.clone()).or_default();
                    for (pos, count) in new_func_map {
                        if count == 0 {
                            continue;
                        }
                        if !func_map.contains_key(&pos) {
                            found_new = true;
                        }
                        let entry = func_map.entry(pos).or_insert(0);
                        *entry += count;
                    }
                }
            }
        }
        found_new
    }
}
