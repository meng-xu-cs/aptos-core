use crate::{
    common::{Account, LanguageSetting, PkgDefinition},
    deps::PkgManifest,
};
use anyhow::Result;
use itertools::Itertools;
use std::{collections::BTreeMap, ops::AddAssign};

mod account;
mod canvas;
mod driver;
mod executor;
mod function;
mod ident;
mod model;
mod mutator;
mod oneshot;
mod prep;
mod typing;

/// Entrypoint for the fuzzer
pub fn run_on(
    pkg_defs: Vec<PkgDefinition>,
    named_accounts: BTreeMap<String, Account>,
    language: LanguageSetting,
    autogen_manifest: PkgManifest,
    seed: Option<u64>,
    num_users: usize,
    _type_recursion_depth: usize,
) -> Result<()> {
    // initialize the tracing executor
    let mut executor = executor::TracingExecutor::new();
    for pkg in &pkg_defs {
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

    let mut stats: BTreeMap<_, usize> = BTreeMap::new();
    let mut i = 0;
    loop {
        for ident in &all_entrypoints {
            log::debug!("running transaction for {ident}");
            let mut fuzzer =
                oneshot::OneshotFuzzer::new(&preparer, executor.clone(), seed.unwrap_or(0));
            let status = fuzzer.run_one(ident)?;
            stats
                .entry(status)
                .and_modify(|t| t.add_assign(1))
                .or_insert(1);
        }
        i += 1;

        let summary = stats.iter().map(|(k, v)| format!("{k}: {v}")).join("\n");
        log::info!("Status after iteration {i}\n{summary}");
    }

    // done
    Ok(())
}
