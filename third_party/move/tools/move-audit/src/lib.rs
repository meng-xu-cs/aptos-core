mod common;
mod deps;
mod package;
mod simulator;
mod subexec;
mod testnet;

// export this symbol
pub use crate::common::LanguageSetting;
use crate::{
    common::Project,
    deps::PkgManifest,
    simulator::Simulator,
    testnet::{execute_runbook, provision_simulator},
};
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use fs_extra::dir::CopyOptions;
use log::{info, LevelFilter};
use regex::Regex;
use std::path::PathBuf;
use tempfile::TempDir;

/// Commands for auditing
#[derive(Subcommand)]
pub enum AuditCommand {
    /// List collected packages in the project
    List,

    /// Run unit tests in the packages (locally, without network)
    Test {
        /// Filter on package level
        #[clap(flatten)]
        pkg_filter: FilterPackage,

        /// Compilation only
        #[clap(long = "compile")]
        compile_only: bool,

        /// Generate documents only
        #[clap(long = "docs", conflicts_with = "compile_only")]
        docs_only: bool,
    },

    /// Run end-to-end runbook in the simulated network
    Exec {
        /// Path to runbook file
        runbook: PathBuf,

        /// Use realistic gas settings
        #[clap(long)]
        realistic_gas: bool,
    },
}

/// Package-level filter
#[derive(Parser)]
pub struct FilterPackage {
    /// Include dependencies
    #[clap(long)]
    include_deps: bool,

    /// Allow-list
    #[clap(long)]
    include_pkg: Option<Vec<String>>,

    /// Deny-list
    #[clap(long)]
    exclude_pkg: Option<Vec<String>>,
}

impl FilterPackage {
    fn apply(&self, pkgs: Vec<(PkgManifest, bool)>) -> Result<Vec<PkgManifest>> {
        let include_regex = match self.include_pkg.as_ref() {
            None => None,
            Some(patterns) => Some(
                patterns
                    .iter()
                    .map(|p| Regex::new(&format!("^{}$", p)).map_err(|e| anyhow!(e)))
                    .collect::<Result<Vec<_>>>()?,
            ),
        };
        let exclude_regex = match self.exclude_pkg.as_ref() {
            None => None,
            Some(patterns) => Some(
                patterns
                    .iter()
                    .map(|p| Regex::new(&format!("^{}$", p)).map_err(|e| anyhow!(e)))
                    .collect::<Result<Vec<_>>>()?,
            ),
        };

        // filtering logic: include first then exclude
        let mut filtered = vec![];
        for (manifest, is_primary) in pkgs {
            if !is_primary && !self.include_deps {
                continue;
            }
            match include_regex.as_ref() {
                None => (),
                Some(regexes) => {
                    if regexes.iter().all(|r| !r.is_match(&manifest.name)) {
                        continue;
                    }
                },
            }
            match exclude_regex.as_ref() {
                None => (),
                Some(regexes) => {
                    if regexes.iter().any(|r| r.is_match(&manifest.name)) {
                        continue;
                    }
                },
            }
            filtered.push(manifest);
        }

        Ok(filtered)
    }
}

fn cmd_list(project: Project) {
    for (manifest, is_primary) in project.pkgs {
        println!(
            "{} [{}] :{}",
            manifest.name,
            manifest.version,
            if is_primary { "primary" } else { "dependency" }
        )
    }
}

fn cmd_test(
    project: Project,
    filter: FilterPackage,
    compile_only: bool,
    docs_only: bool,
) -> Result<()> {
    let Project {
        pkgs,
        named_accounts,
        language,
    } = project;
    for pkg in filter.apply(pkgs)? {
        if compile_only {
            info!("compiling package {}", pkg.name);
            package::build(&pkg, &named_accounts, language, true)?;
        } else if docs_only {
            info!("generating documents for package {}", pkg.name);
            package::gen_docs(&pkg, &named_accounts, language)?;
        } else {
            info!("running unit tests for package {}", pkg.name);
            package::exec_unit_test(&pkg, &named_accounts, language)?;
        }
    }

    // done
    Ok(())
}

fn cmd_exec(project: Project, runbook: PathBuf, realistic_gas: bool) -> Result<()> {
    // initialize the simulator
    let mut simulator = Simulator::new(realistic_gas)?;

    // execute the runbook in the simulator
    let result = provision_simulator(&mut simulator, project)
        .and_then(|_| execute_runbook(&mut simulator, &runbook));

    // clean-up either on success or on failure
    simulator.destroy()?;

    // return the execution result
    result
}

/// Entrypoint on multi-package auditing
pub fn run_on(
    path: PathBuf,
    language: LanguageSetting,
    skip_deps_update: bool,
    verbose: u8,
    command: AuditCommand,
) -> Result<()> {
    // initialize logging
    env_logger::builder()
        .format_timestamp(None)
        .format_target(false)
        .format_module_path(false)
        .filter_level(match verbose {
            0 => LevelFilter::Warn,
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        })
        .init();
    info!("auditing project at path: {}", path.to_string_lossy());

    // copy over the workspace
    let tempdir = TempDir::new()?;
    fs_extra::dir::copy(path, tempdir.path(), &CopyOptions::new())?;

    // resolve the project
    let project = deps::resolve(tempdir.path(), language, skip_deps_update)?;

    // execute the command
    match command {
        AuditCommand::List => {
            cmd_list(project);
        },
        AuditCommand::Test {
            pkg_filter,
            compile_only,
            docs_only,
        } => {
            cmd_test(project, pkg_filter, compile_only, docs_only)?;
        },
        AuditCommand::Exec {
            runbook,
            realistic_gas,
        } => {
            cmd_exec(project, runbook, realistic_gas)?;
        },
    }

    // clean-up
    tempdir.close()?;

    // done
    Ok(())
}
