use crate::{
    common::{Account, LanguageSetting, PkgDefinition},
    deps::PkgManifest,
};
use anyhow::Result;
use itertools::Itertools;
use move_core_types::vm_status::VMStatus;
use std::{collections::BTreeMap, fmt::Display, ops::AddAssign};

mod account;
mod canvas;
mod driver;
mod executor;
mod function;
mod ident;
mod model;
mod prep;
mod typing;

#[derive(Ord, PartialOrd, Eq, PartialEq)]
enum ExecStatus {
    Success,
    AbortIntrinsic,
    AbortDeclared,
    Error,
}

impl Display for ExecStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecStatus::Success => write!(f, "success"),
            ExecStatus::AbortIntrinsic => write!(f, "abort-i"),
            ExecStatus::AbortDeclared => write!(f, "abort-c"),
            ExecStatus::Error => write!(f, "error"),
        }
    }
}

/// Entrypoint for the fuzzer
pub fn run_on(
    pkg_defs: Vec<PkgDefinition>,
    named_accounts: BTreeMap<String, Account>,
    language: LanguageSetting,
    autogen_manifest: PkgManifest,
    num_users: usize,
    type_recursion_depth: usize,
) -> Result<()> {
    // initialize the tracing executor
    let mut executor = executor::TracingExecutor::new();
    for pkg in &pkg_defs {
        // process packages in the order of their dependency chain
        executor.add_new_package(pkg)?
    }
    for _ in 0..num_users {
        executor.add_new_user();
    }

    // TODO: advanced processing
    // build a model on the packages
    // let mut model = model::Model::new();
    // model.provision(&pkg_defs, type_recursion_depth);

    // TODO: replace with advanced processing when ready
    let mut preparer = prep::Preparer::new(&pkg_defs);
    preparer.generate_scripts(&named_accounts, language, &autogen_manifest);

    // stage 1: per-function fuzzing
    let all_entrypoints = preparer.all_entry_idents();

    let mut stats: BTreeMap<_, usize> = [
        (ExecStatus::Success, 0),
        (ExecStatus::AbortIntrinsic, 0),
        (ExecStatus::AbortDeclared, 0),
        (ExecStatus::Error, 0),
    ]
    .into_iter()
    .collect();

    let mut i = 0;
    loop {
        for ident in &all_entrypoints {
            log::debug!("running transaction for {ident}");
            let payload = preparer.generate_random_payload(ident);
            let (status, _) = executor.run_payload_with_random_sender(payload)?;
            match status {
                VMStatus::Executed => stats.get_mut(&ExecStatus::Success).unwrap().add_assign(1),
                VMStatus::Error { .. } => stats.get_mut(&ExecStatus::Error).unwrap().add_assign(1),
                VMStatus::ExecutionFailure { .. } => stats
                    .get_mut(&ExecStatus::AbortIntrinsic)
                    .unwrap()
                    .add_assign(1),
                VMStatus::MoveAbort { .. } => stats
                    .get_mut(&ExecStatus::AbortDeclared)
                    .unwrap()
                    .add_assign(1),
            }
        }
        i += 1;

        let summary = stats.iter().map(|(k, v)| format!("{k}: {v}")).join("\n");
        log::info!("Status after iteration {i}\n{summary}");
    }

    // done
    Ok(())
}
