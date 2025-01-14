mod common;
mod deps;
mod fuzz;
mod package;
mod simulator;
mod subexec;
mod testnet;

// export this symbol
pub use crate::common::LanguageSetting;
use crate::{
    common::{PkgDeclaration, PkgDefinition, Project},
    fuzz::model::FuzzModel,
    simulator::Simulator,
    testnet::{execute_runbook, provision_simulator},
};
use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use fs_extra::dir::CopyOptions;
use log::{info, LevelFilter};
use move_model::metadata::LanguageVersion;
use regex::Regex;
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use walkdir::WalkDir;

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

        /// Subsequent package-level command
        #[clap(subcommand)]
        command: Option<PkgCommand>,
    },

    /// Run end-to-end runbook in the simulated network
    Exec {
        /// Path to runbook file
        #[clap(long)]
        runbook: Option<PathBuf>,

        /// Use realistic gas settings
        #[clap(long)]
        realistic_gas: bool,
    },

    /// Run fuzz testing on the project
    Fuzz {
        /// Mark the main packages to fuzz
        #[clap(flatten)]
        pkg_filter: FilterPackage,
    },
}

/// Commands for package-level testing
#[derive(Subcommand)]
pub enum PkgCommand {
    Compile,
    Format {
        #[clap(long)]
        config: Option<PathBuf>,
    },
    Doc,
    Filter {
        pattern: String,
    },
}

/// Package-level filter
#[derive(Parser)]
pub struct FilterPackage {
    /// Include dependencies
    #[clap(long)]
    include_deps: bool,

    /// Include Aptos Framework packages
    #[clap(long)]
    include_framework: bool,

    /// Allow-list
    #[clap(long)]
    include_pkg: Option<Vec<String>>,

    /// Deny-list
    #[clap(long)]
    exclude_pkg: Option<Vec<String>>,
}

impl FilterPackage {
    fn apply(&self, pkgs: Vec<PkgDeclaration>) -> Result<Vec<PkgDeclaration>> {
        let include_regex = match self.include_pkg.as_ref() {
            None => None,
            Some(patterns) => Some(
                patterns
                    .iter()
                    .map(|p| Regex::new(&format!("^{p}$")).map_err(|e| anyhow!(e)))
                    .collect::<Result<Vec<_>>>()?,
            ),
        };
        let exclude_regex = match self.exclude_pkg.as_ref() {
            None => None,
            Some(patterns) => Some(
                patterns
                    .iter()
                    .map(|p| Regex::new(&format!("^{p}$")).map_err(|e| anyhow!(e)))
                    .collect::<Result<Vec<_>>>()?,
            ),
        };

        // filtering logic: include first then exclude
        let mut filtered = vec![];
        for pkg in pkgs {
            // filter based on type
            match &pkg {
                PkgDeclaration::Framework(_) if !self.include_framework => {
                    continue;
                },
                PkgDeclaration::Dependency(_) if !self.include_deps => {
                    continue;
                },
                _ => (),
            }

            // filter based on name
            let manifest = pkg.as_manifest();
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

            // if the control flow reaches here, we need to include this package
            filtered.push(pkg);
        }

        Ok(filtered)
    }
}

fn cmd_list(project: Project) {
    for pkg in project.pkgs {
        let (kind, manifest) = match pkg {
            PkgDeclaration::Primary(manifest) => ("primary", manifest),
            PkgDeclaration::Dependency(manifest) => ("dependency", manifest),
            PkgDeclaration::Framework(manifest) => ("framework", manifest),
        };
        println!("{} [{}] :{kind}", manifest.name, manifest.version,)
    }
}

fn cmd_test(
    project: Project,
    pkg_filter: FilterPackage,
    command: Option<PkgCommand>,
) -> Result<()> {
    let Project {
        pkgs,
        named_accounts,
        language,
    } = project;
    for pkg in pkg_filter.apply(pkgs)? {
        let manifest = pkg.as_manifest();
        match command.as_ref() {
            None => {
                info!("running unit tests for package {}", manifest.name);
                package::exec_unit_test(manifest, &named_accounts, language, None)?;
            },
            Some(PkgCommand::Filter { pattern }) => {
                info!("running unit tests for package {}", manifest.name);
                package::exec_unit_test(manifest, &named_accounts, language, Some(pattern))?;
            },
            Some(PkgCommand::Compile) => {
                info!("compiling package {}", manifest.name);
                package::build(manifest, &named_accounts, language, true)?;
            },
            Some(PkgCommand::Format { config }) => {
                info!("formatting package {}", manifest.name);
                package::format_code(manifest, config.as_deref())?;
            },
            Some(PkgCommand::Doc) => {
                info!("generating documents for package {}", manifest.name);
                package::gen_docs(manifest, &named_accounts, language)?;
            },
        }
    }

    // done
    Ok(())
}

fn cmd_exec(project: &Project, runbook: &Path, realistic_gas: bool) -> Result<()> {
    // initialize the simulator
    let mut simulator = Simulator::new(project.language, realistic_gas)?;

    // execute the runbook in the simulator
    let result = provision_simulator(&mut simulator, project)
        .and_then(|_| execute_runbook(&mut simulator, runbook));

    // clean-up either on success or on failure
    simulator.destroy()?;

    // return the execution result
    result
}

fn cmd_fuzz(project: Project, pkg_filter: FilterPackage) -> Result<()> {
    // fuzzing is only supported on the latest compiler
    if !matches!(project.language.version, LanguageVersion::V2_1) {
        bail!(
            "fuzzing is not supported on language version: {}",
            project.language.version
        );
    }

    // we need to see all packages unless the package is explicitly excluded
    if !pkg_filter.include_framework {
        bail!("fuzzer requires the `--include-framework` flag");
    }
    if !pkg_filter.include_deps {
        bail!("fuzzer requires the `--include-deps` flag");
    }

    // build all packages initially, this is also a sanity check on the packages
    let Project {
        pkgs,
        named_accounts,
        language,
    } = project;

    let mut compiled_packages = vec![];
    for pkg in pkg_filter.apply(pkgs)? {
        let manifest = pkg.as_manifest();
        info!("compiling package {}", manifest.name);
        let pkg_built = package::build(manifest, &named_accounts, language, false)?;

        let pkg_def = match pkg {
            PkgDeclaration::Primary(_) => PkgDefinition::Primary(pkg_built),
            PkgDeclaration::Dependency(_) => PkgDefinition::Dependency(pkg_built),
            PkgDeclaration::Framework(_) => PkgDefinition::Framework(pkg_built),
        };
        compiled_packages.push(pkg_def);
    }

    // build a model about the packages to be fuzzed
    info!(
        "building a model for {} packages to be fuzzed",
        compiled_packages.len()
    );
    FuzzModel::new(&compiled_packages);

    // TODO: fuzzing logic

    // done
    Ok(())
}

/// Entrypoint on multi-package auditing
pub fn run_on(
    path: PathBuf,
    language: LanguageSetting,
    name_aliases: Vec<String>,
    in_place: bool,
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

    // construct the named aliases
    let mut address_aliases: Vec<BTreeSet<String>> = vec![];
    for item in name_aliases {
        let mut iter = item.split('=');
        let (lhs, rhs) = iter
            .next()
            .and_then(|lhs| iter.next().map(|rhs| (lhs, rhs)))
            .ok_or_else(|| anyhow!("invalid alias declaration: {}", item))?;
        if iter.next().is_some() {
            bail!("invalid alias declaration: {}", item);
        }
        let lhs_pos = address_aliases.iter().position(|set| set.contains(lhs));
        let rhs_pos = address_aliases.iter().position(|set| set.contains(rhs));

        // merge the sets
        match (lhs_pos, rhs_pos) {
            (None, None) => {
                address_aliases.push([lhs.to_string(), rhs.to_string()].into_iter().collect());
            },
            (Some(lhs_idx), None) => {
                address_aliases
                    .get_mut(lhs_idx)
                    .unwrap()
                    .insert(rhs.to_string());
            },
            (None, Some(rhs_idx)) => {
                address_aliases
                    .get_mut(rhs_idx)
                    .unwrap()
                    .insert(lhs.to_string());
            },
            (Some(lhs_idx), Some(rhs_idx)) => {
                let mut rhs_set = BTreeSet::new();
                rhs_set.append(address_aliases.get_mut(rhs_idx).unwrap());
                address_aliases
                    .get_mut(lhs_idx)
                    .unwrap()
                    .append(&mut rhs_set);
                address_aliases.swap_remove(rhs_idx);
            },
        }
    }

    // copy over the workspace
    let tempdir = if in_place {
        None
    } else {
        let dir = TempDir::new()?;
        fs_extra::dir::copy(&path, dir.path(), &CopyOptions::new())?;
        Some(dir)
    };
    let workdir = tempdir.as_ref().map_or(path.as_path(), |d| d.path());

    // resolve the project
    let project = deps::resolve(
        workdir,
        language,
        address_aliases.into_iter().collect(),
        skip_deps_update,
    )?;

    // execute the command
    match command {
        AuditCommand::List => {
            cmd_list(project);
        },
        AuditCommand::Test {
            pkg_filter,
            command,
        } => {
            cmd_test(project, pkg_filter, command)?;
        },
        AuditCommand::Exec {
            runbook,
            realistic_gas,
        } => {
            let mut targets = vec![];
            match runbook {
                None => {
                    for entry in WalkDir::new(workdir) {
                        let entry = entry?;
                        if entry.path().extension().map_or(false, |ext| ext == "json") {
                            targets.push(entry.path().to_owned());
                        }
                    }
                },
                Some(path) => targets.push(path),
            }
            for target in targets {
                cmd_exec(&project, &target, realistic_gas)?;
            }
        },
        AuditCommand::Fuzz { pkg_filter } => {
            cmd_fuzz(project, pkg_filter)?;
        },
    }

    // clean-up
    if let Some(dir) = tempdir {
        dir.close()?;
    }

    // done
    Ok(())
}
