mod deps;
mod util;

use crate::deps::{PkgManifest, PkgNamedAddr};
use anyhow::Result;
use clap::Subcommand;
use log::{debug, LevelFilter};
use std::{collections::BTreeMap, path::Path};
use walkdir::WalkDir;

/// Commands for auditing
#[derive(Subcommand)]
pub enum AuditCommand {
    List,
}

/// A Move audit project composed by a list of packages to audit
pub struct Project {
    pub pkgs: BTreeMap<String, (PkgManifest, bool)>,
    pub named_addresses: BTreeMap<String, PkgNamedAddr>,
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

/// Entrypoint on multi-package auditing
pub fn run_on(
    path: &Path,
    skip_deps_update: bool,
    verbosity: u8,
    command: AuditCommand,
) -> Result<()> {
    // initialize logging
    env_logger::builder()
        .format_timestamp(None)
        .format_target(false)
        .format_module_path(false)
        .filter_level(match verbosity {
            0 => LevelFilter::Warn,
            1 => LevelFilter::Info,
            2 => LevelFilter::Debug,
            _ => LevelFilter::Trace,
        })
        .init();
    debug!("auditing project at path: {}", path.to_string_lossy());

    // find Move packages with the project directory
    let mut pkgs = vec![];
    for entry in WalkDir::new(path) {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.file_name().expect("filename") == "Move.toml" {
            pkgs.push(entry_path.parent().expect("parent").to_path_buf());
        }
    }

    // resolve the project
    let project = deps::resolve(pkgs, skip_deps_update)?;

    // execute the command
    match command {
        AuditCommand::List => cmd_list(project),
    }

    // done
    Ok(())
}
