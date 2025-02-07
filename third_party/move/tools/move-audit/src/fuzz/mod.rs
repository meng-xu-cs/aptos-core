use crate::{
    common::{Account, LanguageSetting, PkgDefinition},
    deps::PkgManifest,
};
use anyhow::Result;
use std::collections::BTreeMap;

mod account;
mod canvas;
mod driver;
mod executor;
mod function;
mod ident;
mod model;
mod prep;
mod typing;

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

    let mut i = 0;
    loop {
        for ident in &all_entrypoints {
            let payload = preparer.generate_random_payload(ident);
            executor.run_payload_with_random_sender(payload)?;
        }
        i += 1;
        if i % 1000 == 0 {
            log::info!("Tried {i} iterations");
        }
    }

    // done
    Ok(())
}
