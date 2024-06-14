use crate::deps::{PkgManifest, PkgNamedAddr};
use anyhow::{bail, Result};
use std::{collections::BTreeMap, fs, path::PathBuf};

const WORKSPACE_DIRECTORY: &str = ".aptos";

/// A Move audit project composed by a list of packages to audit
pub struct Project {
    pub root: PathBuf,
    pub pkgs: BTreeMap<String, (PkgManifest, bool)>,
    pub named_addresses: BTreeMap<String, PkgNamedAddr>,
}

/// A Move audit workspace inside the project (typically under the .aptos dir)
pub struct Workspace {
    pub base: PathBuf,
    pub config: PathBuf,
    pub testnet: PathBuf,
}

impl Workspace {
    fn new(base: PathBuf) -> Self {
        Self {
            config: base.join("config.yaml"),
            testnet: base.join("testnet"),
            base,
        }
    }

    /// Load from an existing workspace
    pub fn load(project: &Project) -> Result<Self> {
        let base = project.root.join(WORKSPACE_DIRECTORY);
        if !base.is_dir() {
            bail!("workspace is not ready, please run the init command");
        }
        Ok(Self::new(base))
    }

    /// Create a new workspace
    pub fn init(project: &Project, force: bool) -> Result<Self> {
        // prepare the base
        let base = project.root.join(WORKSPACE_DIRECTORY);
        if base.exists() {
            if !base.is_dir() {
                bail!("workspace exists but is not a directory");
            }
            if !force {
                bail!("workspace already initialized, use --force to force a recreation");
            }
            fs::remove_dir_all(&base)?;
        }
        fs::create_dir_all(&base)?;

        // done
        Ok(Self::new(base))
    }
}
