use crate::fuzz::{
    executor::TracingExecutor,
    mutator::Mutator,
    prep::{EntrypointIdent, Preparer},
};
use anyhow::Result;
use aptos_types::transaction::{ExecutionStatus, TransactionStatus};
use move_core_types::vm_status::{AbortLocation, StatusCode, VMStatus};
use std::fmt::Display;

/// Status of one execution
#[derive(Ord, PartialOrd, Eq, PartialEq)]
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
                VMStatus::MoveAbort(location, abort_code),
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
pub struct OneshotFuzzer<'a> {
    preparer: &'a Preparer,
    executor: TracingExecutor,
    mutator: Mutator,
}

impl<'a> OneshotFuzzer<'a> {
    /// Create a new one-shot fuzzer
    pub fn new(preparer: &'a Preparer, executor: TracingExecutor, seed: u64) -> Self {
        let mutator = Mutator::new(seed, executor.all_addresses_by_kind());
        Self {
            preparer,
            executor,
            mutator,
        }
    }

    /// Execute one entry-point
    pub fn run_one(&mut self, ident: &EntrypointIdent) -> Result<ExecStatus> {
        // prepare
        let sender = self.mutator.random_signer();
        let payload = self
            .preparer
            .generate_random_payload(&mut self.mutator, ident);

        // execute
        let status_pair = self.executor.run_payload_with_sender(sender, payload)?;
        Ok(status_pair.into())
    }
}
