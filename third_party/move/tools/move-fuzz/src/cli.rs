// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    deps::{self, PkgDeclaration, PkgDefinition, PkgKind, PkgManifest, Project},
    fuzzer,
    language::LanguageSetting,
    package,
    simulator::Simulator,
    testnet::{execute_runbook, provision_simulator},
};
use anyhow::{anyhow, bail, Result};
use aptos_framework::extended_checks;
use aptos_vm::natives;
use clap::{Parser, Subcommand};
use fs_extra::dir;
use log::{info, LevelFilter};
use move_cli::base::test_validation;
use move_model::model::GlobalEnv;
use regex::Regex;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use tempfile::TempDir;
use walkdir::WalkDir;

/// Commands for move-fuzz
#[derive(Subcommand)]
pub enum FuzzCommand {
    /// List collected packages in the project
    List,

    /// Build the packages
    Build {
        /// Filter on package level
        #[clap(flatten)]
        pkg_filter: FilterPackage,

        /// Development build (e.g., including tests)
        #[clap(long)]
        dev: bool,
    },

    /// Run unit tests in the packages (locally, without network)
    Test {
        /// Filter on package level
        #[clap(flatten)]
        pkg_filter: FilterPackage,

        /// Test case filter
        #[clap(long)]
        test_filter: Option<String>,

        /// Gas metering
        #[clap(long)]
        gas: bool,

        /// Single thread
        #[clap(long)]
        single_thread: bool,
    },

    /// Run end-to-end runbook in a locally simulated network
    Exec {
        /// Path to runbook file or a directory
        #[clap(long)]
        runbook: Option<PathBuf>,

        /// Use realistic gas settings
        #[clap(long)]
        realistic_gas: bool,
    },

    /// Run the entire fuzz testing on the project
    Auto {
        /// Mark the main packages to fuzz
        #[clap(flatten)]
        pkg_filter: FilterPackage,

        /// Seed for all randomness in the fuzzing process
        #[clap(long)]
        seed: Option<u64>,

        /// Max trace depth
        #[clap(long, default_value = "5")]
        max_trace_depth: usize,

        /// Max call repetition
        #[clap(long, default_value = "2")]
        max_call_repetition: usize,
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
    pub fn apply(&self, pkgs: Vec<PkgDeclaration>) -> Result<Vec<PkgDeclaration>> {
        let include_regex = match self.include_pkg.as_ref() {
            None => None,
            Some(patterns) => Some(
                patterns
                    .iter()
                    .map(|p| {
                        Regex::new(&format!("^{p}$"))
                            .map_err(|e| anyhow!("invalid regex '{p}': {e}"))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
        };
        let exclude_regex = match self.exclude_pkg.as_ref() {
            None => None,
            Some(patterns) => Some(
                patterns
                    .iter()
                    .map(|p| {
                        Regex::new(&format!("^{p}$"))
                            .map_err(|e| anyhow!("invalid regex '{p}': {e}"))
                    })
                    .collect::<Result<Vec<_>>>()?,
            ),
        };

        // filtering logic: include first then exclude
        let mut filtered = vec![];
        for pkg in pkgs {
            // filter based on kind
            match &pkg.kind {
                PkgKind::Framework if !self.include_framework => {
                    continue;
                },
                PkgKind::Dependency if !self.include_deps => {
                    continue;
                },
                _ => (),
            }

            // filter based on name
            let manifest = &pkg.manifest;
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

/// Entrypoint on move-fuzz from the CLI
pub fn run_on(
    path: PathBuf,
    subdirs: Vec<PathBuf>,
    language: LanguageSetting,
    name_aliases: Vec<String>,
    resource_accounts: Vec<String>,
    in_place: bool,
    skip_deps_update: bool,
    verbose: u8,
    command: FuzzCommand,
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
    info!("analyzing project at path: {}", path.to_string_lossy());

    // sanity check paths
    if !path.exists() {
        bail!("project path does not exist: {}", path.display());
    }
    for item in &subdirs {
        let path_subdir = path.join(item);
        if !path_subdir.exists() {
            bail!(
                "project subdirectory does not exist: {}",
                path_subdir.display()
            );
        }
    }

    // construct the named aliases
    let mut address_aliases: Vec<BTreeSet<String>> = vec![];
    for item in name_aliases {
        let (lhs, rhs) = split_on_char(&item, '=')
            .ok_or_else(|| anyhow!("invalid alias declaration: {item}"))?;

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

    // mark resource accounts created from regular addresses
    let mut resource_mapping = BTreeMap::new();
    for item in resource_accounts {
        let (resource, base, seed) = split_on_char(&item, '=')
            .and_then(|(resource, rest)| {
                split_on_char(rest, ':').map(|(base, seed)| (resource, base, seed))
            })
            .ok_or_else(|| anyhow!("invalid resource declaration: {item}"))?;

        resource_mapping.insert(resource.to_string(), (base.to_string(), seed.to_string()));
    }

    // copy over the workspace
    let tempdir = if in_place {
        None
    } else {
        let dir = TempDir::new()?;
        dir::copy(
            &path,
            dir.path(),
            &dir::CopyOptions::new().content_only(true),
        )?;
        Some(dir)
    };
    let workdir = tempdir
        .as_ref()
        .map_or(path.as_path(), |d| d.path())
        .canonicalize()?;

    // resolve the project
    let project = deps::resolve(
        &workdir,
        subdirs
            .into_iter()
            .map(|p| {
                workdir
                    .join(p)
                    .canonicalize()
                    .expect("canonicalized path in work directory")
            })
            .collect(),
        language,
        address_aliases.into_iter().collect(),
        resource_mapping,
        skip_deps_update,
    )?;

    // execute the command
    match command {
        FuzzCommand::List => {
            cmd_list(project);
        },
        FuzzCommand::Build { pkg_filter, dev } => {
            cmd_build(project, pkg_filter, dev)?;
        },
        FuzzCommand::Test {
            pkg_filter,
            test_filter,
            gas,
            single_thread,
        } => {
            cmd_test(project, pkg_filter, test_filter, gas, single_thread)?;
        },
        FuzzCommand::Exec {
            runbook,
            realistic_gas,
        } => match runbook {
            None => cmd_exec(&project, None, realistic_gas)?,
            Some(path) => {
                let mut targets = vec![];
                if path.is_file() {
                    targets.push(path);
                } else {
                    for entry in WalkDir::new(&path) {
                        let entry = entry?;
                        if entry.path().extension().is_some_and(|ext| ext == "json") {
                            targets.push(entry.path().to_owned());
                        }
                    }
                }
                for target in targets {
                    cmd_exec(&project, Some(&target), realistic_gas)?;
                }
            },
        },
        FuzzCommand::Auto {
            pkg_filter,
            seed,
            max_trace_depth,
            max_call_repetition,
        } => {
            cmd_auto(
                &workdir,
                project,
                pkg_filter,
                seed,
                max_trace_depth,
                max_call_repetition,
            )?;
        },
    }

    // clean-up
    if let Some(dir) = tempdir {
        dir.close()?;
    }

    // done
    Ok(())
}

fn cmd_list(project: Project) {
    for pkg in project.pkgs {
        println!(
            "{} [{}] :{:?}",
            pkg.manifest.name, pkg.manifest.version, pkg.kind
        );
    }
}

fn cmd_build(project: Project, pkg_filter: FilterPackage, dev_mode: bool) -> Result<()> {
    let Project {
        pkgs,
        named_accounts,
        language,
    } = project;

    for pkg in pkg_filter.apply(pkgs)? {
        package::build(&pkg.manifest, &named_accounts, language, dev_mode)?;
    }

    Ok(())
}

fn cmd_test(
    project: Project,
    pkg_filter: FilterPackage,
    test_filter: Option<String>,
    gas: bool,
    single_thread: bool,
) -> Result<()> {
    let Project {
        pkgs,
        named_accounts,
        language,
    } = project;

    // configure hooks ahead of time for unit tests
    natives::configure_for_unit_test();
    configure_extended_checks_for_unit_test();

    // run tests on each of the packages
    for pkg in pkg_filter.apply(pkgs)? {
        package::unit_test(
            &pkg.manifest,
            &named_accounts,
            language,
            test_filter.as_deref(),
            gas,
            single_thread,
        )?;
    }

    Ok(())
}

fn cmd_auto(
    workdir: &Path,
    project: Project,
    mut pkg_filter: FilterPackage,
    seed: Option<u64>,
    max_trace_depth: usize,
    max_call_repetition: usize,
) -> Result<()> {
    // we need to see all packages unless the package is explicitly excluded
    if !pkg_filter.include_framework {
        pkg_filter.include_framework = true;
        info!("fuzzer overrides the `--include-framework` flag and sets it to true");
    }
    if !pkg_filter.include_deps {
        pkg_filter.include_deps = true;
        info!("fuzzer overrides the `--include-deps` flag and sets it to true");
    }

    // build all packages initially, this is also a sanity check on the packages
    let Project {
        pkgs,
        named_accounts,
        language,
    } = project;

    let mut autogen_deps = BTreeMap::new();
    let mut pkg_defs = vec![];
    for pkg_decl in pkg_filter.apply(pkgs)? {
        let manifest = &pkg_decl.manifest;
        let existing = autogen_deps.insert(manifest.name.clone(), manifest.clone());
        assert!(existing.is_none());

        log::debug!("compiling package {}", manifest.name);
        let pkg_built = package::build(manifest, &named_accounts, language, false)?;

        // NOTE: as `pkgs` are in the topological order of the dependency graph, so are `pkg_defs`
        pkg_defs.push(PkgDefinition {
            kind: pkg_decl.kind,
            package: pkg_built,
        });
    }

    // prepare the autogen package directory to host derived Move code
    let autogen_dir = workdir.join("autogen");
    if autogen_dir.exists() {
        bail!("autogen directory already exists");
    }
    fs::create_dir_all(&autogen_dir)?;

    let autogen_name = "Autogen".to_string();
    let autogen_deps_str = autogen_deps
        .iter()
        .map(|(key, val)| format!("{key} = {{ local = \"{}\" }}", val.path.display()))
        .collect::<Vec<_>>()
        .join("\n");
    let autogen_toml = format!(
        r#"
[package]
name = "{autogen_name}"
version = "1.0.0"
upgrade_policy = "compatible"
authors = []

[dependencies]
{autogen_deps_str}
"#
    );
    fs::write(autogen_dir.join("Move.toml"), autogen_toml)?;
    fs::create_dir(autogen_dir.join("sources"))?;

    // create a manifest for the autogen package
    let autogen_manifest = PkgManifest {
        name: autogen_name,
        path: autogen_dir,
        version: (1, 0, 0).into(),
        deps: autogen_deps,
        named_addresses: BTreeMap::new(),
    };

    // done with preparation, now call the fuzzer
    fuzzer::entrypoint(
        pkg_defs,
        named_accounts,
        language,
        autogen_manifest,
        seed,
        max_trace_depth,
        max_call_repetition,
    )
}

fn cmd_exec(project: &Project, runbook: Option<&Path>, realistic_gas: bool) -> Result<()> {
    // initialize the simulator
    let mut simulator = Simulator::new(project.language, realistic_gas)?;
    provision_simulator(&mut simulator, project)?;

    // execute the runbook in the simulator
    let result = match runbook {
        None => Ok(()),
        Some(path) => execute_runbook(&mut simulator, path),
    };

    // clean-up either on success or on failure
    simulator.destroy()?;

    // return the execution result
    result
}

/// Utility: split on a given char
fn split_on_char(s: &str, sep: char) -> Option<(&str, &str)> {
    let mut iter = s.split(sep);
    let p1 = iter.next()?;
    let p2 = iter.next()?;
    if iter.next().is_some() {
        return None;
    }
    Some((p1, p2))
}

/// Configures the unit test validation hook to run the extended checker.
fn configure_extended_checks_for_unit_test() {
    fn validate(env: &GlobalEnv) {
        extended_checks::run_extended_checks(env);
    }
    test_validation::set_validation_hook(Box::new(validate));
}
