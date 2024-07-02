mod common;
mod config;
mod deps;
mod package;
mod testnet;

use crate::{
    common::{Project, Workspace},
    deps::PkgManifest,
};
use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use log::{debug, info, LevelFilter};
use regex::Regex;
use std::{collections::BTreeMap, path::PathBuf};

/// Commands for auditing
#[derive(Subcommand)]
pub enum AuditCommand {
    /// Initialize the workspace
    Init {
        /// Clean-up previous states
        #[clap(long)]
        force: bool,
    },

    /// List collected packages in the project
    List,

    /// Run unit tests in the packages (locally, without network)
    Test {
        /// Filter on package level
        #[clap(flatten)]
        pkg_filter: FilterPackage,

        /// Compilation only (skip unit tests)
        #[clap(long)]
        compile_only: bool,
    },

    /// Run end-to-end scripts in the simulated network
    Exec {
        /// Path to a concrete script file
        #[clap(short, long)]
        script: Option<PathBuf>,
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
    fn apply(&self, pkgs: BTreeMap<String, (PkgManifest, bool)>) -> Result<Vec<PkgManifest>> {
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
        for (name, (manifest, is_primary)) in pkgs {
            if !is_primary && !self.include_deps {
                continue;
            }
            match include_regex.as_ref() {
                None => (),
                Some(regexes) => {
                    if regexes.iter().all(|r| !r.is_match(name.as_str())) {
                        continue;
                    }
                },
            }
            match exclude_regex.as_ref() {
                None => (),
                Some(regexes) => {
                    if regexes.iter().any(|r| r.is_match(name.as_str())) {
                        continue;
                    }
                },
            }
            filtered.push(manifest);
        }

        Ok(filtered)
    }
}

fn cmd_init(project: Project, force: bool) -> Result<()> {
    // prepare the workspace
    let wks = Workspace::init(&project, force)?;

    // launch the local testnet
    let cmd = testnet::launch_local_testnet(&project.root, &wks, true)?;

    // populate the profiles
    let result = testnet::init_local_testnet_profiles(&project);

    // shutdown the local testnet
    cmd.interrupt()?;

    // return the profile initialization result
    result
}

fn cmd_list(project: Project) {
    for (name, (manifest, is_primary)) in project.pkgs {
        println!(
            "{} [{}] :{}",
            name,
            manifest.version,
            if is_primary { "primary" } else { "dependency" }
        )
    }
}

fn cmd_test(project: Project, filter: FilterPackage, compile_only: bool) -> Result<()> {
    let Project {
        root: _,
        pkgs,
        named_accounts,
    } = project;
    for pkg in filter.apply(pkgs)? {
        info!("running unit tests for package {}", pkg.name);
        package::exec_unit_test(&pkg, &named_accounts, compile_only)?;
    }

    // done
    Ok(())
}

fn cmd_exec(project: Project) {
    for (name, (manifest, is_primary)) in project.pkgs {
        println!(
            "{} [{}] :{}",
            name,
            manifest.version,
            if is_primary { "primary" } else { "dependency" }
        )
    }
}

/// Entrypoint on multi-package auditing
pub fn run_on(
    path: PathBuf,
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
    debug!("auditing project at path: {}", path.to_string_lossy());

    // resolve the project
    let project = deps::resolve(path, skip_deps_update)?;

    // execute the command
    match command {
        AuditCommand::Init { force } => {
            cmd_init(project, force)?;
        },
        AuditCommand::List => {
            cmd_list(project);
        },
        AuditCommand::Test {
            pkg_filter,
            compile_only,
        } => {
            cmd_test(project, pkg_filter, compile_only)?;
        },
        AuditCommand::Exec { .. } => {
            cmd_exec(project);
        },
    }

    // done
    Ok(())
}
