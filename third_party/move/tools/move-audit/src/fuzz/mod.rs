use crate::common::PkgDefinition;
use anyhow::Result;

mod account;
mod driver;
mod entrypoint;
mod executor;
mod ident;
mod model;
mod typing;

/// Entrypoint for the fuzzer
pub fn run_on(pkg_defs: Vec<PkgDefinition>, type_recursion_depth: usize) -> Result<()> {
    // initialize the tracing executor
    let mut executor = executor::TracingExecutor::new();
    executor.provision(&pkg_defs)?;

    // build a model on the packages
    let mut model = model::Model::new();
    model.provision(&pkg_defs, type_recursion_depth);

    // done
    Ok(())
}
