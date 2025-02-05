use crate::{
    common::{Account, PkgDefinition},
    deps::PkgManifest,
    LanguageSetting,
};
use anyhow::Result;
use std::collections::BTreeMap;

mod account;
mod basics;
mod canvas;
mod driver;
mod executor;
mod function;
mod ident;
mod model;
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

    // TODO: replace with advanced processing when ready
    let mut preparer = basics::Preparer::new(&pkg_defs);
    preparer.generate_scripts(&named_accounts, language, &autogen_manifest);

    // TODO: advanced processing
    // build a model on the packages
    // let mut model = model::Model::new();
    // model.provision(&pkg_defs, type_recursion_depth);

    // done
    Ok(())
}
