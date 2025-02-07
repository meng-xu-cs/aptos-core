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
    type_recursion_depth: usize,
) -> Result<()> {
    // initialize the tracing executor
    let mut executor = executor::TracingExecutor::new();
    executor.provision(&pkg_defs)?;

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
            preparer.generate_random_payload(ident);
        }
        i += 1;
        if i % 1000 == 0 {
            log::info!("Tried {i} iterations");
        }
    }

    // done
    Ok(())
}
