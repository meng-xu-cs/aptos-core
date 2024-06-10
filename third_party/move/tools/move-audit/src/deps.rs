use crate::Project;
use anyhow::{bail, Result};
use log::debug;
use move_core_types::account_address::AccountAddress;
use move_package::{
    resolution::resolution_graph::ResolutionGraph,
    source_package::{
        layout::SourcePackageLayout,
        manifest_parser::parse_move_manifest_from_file,
        parsed_manifest::{SourceManifest, Version},
    },
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Display, Formatter},
    path::PathBuf,
};

/// Mark where the package being audited is stored
#[derive(Eq, PartialEq)]
pub enum PkgLocation {
    Local {
        path: PathBuf,
    },
    Remote {
        url: String,
        rev: String,
        subdir: PathBuf,
        download_to: PathBuf,
    },
}

impl PkgLocation {
    pub fn path(&self) -> PathBuf {
        match self {
            Self::Local { path, .. } => path.clone(),
            Self::Remote {
                download_to,
                subdir,
                ..
            } => download_to.join(subdir),
        }
    }
}

impl Display for PkgLocation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local { path } => write!(f, "fs://{}", path.to_string_lossy()),
            Self::Remote {
                url,
                rev,
                subdir,
                download_to,
            } => write!(
                f,
                "git://{}:{}/{}->{}",
                url,
                rev,
                subdir.to_string_lossy(),
                download_to.to_string_lossy()
            ),
        }
    }
}

/// Mark the version of the package being audited
#[derive(Eq, PartialEq)]
pub struct PkgVersion {
    major: u64,
    minor: u64,
    fix: u64,
}

impl From<Version> for PkgVersion {
    fn from(value: Version) -> Self {
        let (major, minor, fix) = value;
        Self { major, minor, fix }
    }
}

impl Display for PkgVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.fix)
    }
}

/// Named address within a package
#[derive(Copy, Clone)]
pub enum PkgNamedAddr {
    Unset,
    Devel(AccountAddress),
    Fixed(AccountAddress),
}

/// Manifest of the package being audited
pub struct PkgManifest {
    pub name: String,
    pub path: PathBuf,
    pub version: PkgVersion,
    pub named_addresses: BTreeMap<String, PkgNamedAddr>,
}

fn analyze_package_manifest(
    location: PkgLocation,
    name_opt: Option<String>,
    version: Option<PkgVersion>,
    analyzed_pkgs: &mut BTreeMap<String, PkgManifest>,
    stack: &mut Vec<String>,
    skip_deps_update: bool,
) -> Result<String> {
    // locate and check package root
    let root = location.path();
    if SourcePackageLayout::try_find_root(&root)? != root {
        bail!(
            "invalid package location: {}, manifest file not found",
            root.to_string_lossy()
        );
    }

    // load the manifest
    let manifest = parse_move_manifest_from_file(&root)?;
    let SourceManifest {
        package,
        addresses: _,
        dev_address_assignments: _,
        build: _,
        dependencies,
        dev_dependencies,
    } = manifest;

    // check name match
    let pkg_name = package.name.to_string();
    match name_opt {
        None => (),
        Some(declared_name) => {
            if declared_name != pkg_name {
                bail!(
                    "dependency name mismatch: declared {}, found {}",
                    declared_name,
                    pkg_name
                );
            }
        },
    }

    // check version match
    let pkg_version = package.version.into();
    match version {
        None => (),
        Some(declared_version) => {
            if declared_version != pkg_version {
                bail!(
                    "dependency {} version mismatch: declared {}, found {}",
                    pkg_name,
                    declared_version,
                    pkg_version
                );
            }
        },
    }

    // check if we have analyzed this package
    match analyzed_pkgs.get(&pkg_name) {
        None => (),
        Some(manifest) => {
            // confirm that it is a match
            if root != manifest.path {
                bail!(
                    "location mismatch of base package {}: found {}, analyzed {}",
                    pkg_name,
                    root.to_string_lossy(),
                    manifest.path.to_string_lossy(),
                );
            }
            if pkg_version != manifest.version {
                bail!(
                    "version mismatch of base package {}: found {}, analyzed {}",
                    pkg_name,
                    pkg_version,
                    manifest.version,
                );
            }

            // we have already analyzed this package
            return Ok(pkg_name);
        },
    }

    // ensure that there are no cyclic dependencies on the package level
    if stack.contains(&pkg_name) {
        bail!("cyclic dependency on package {}", pkg_name);
    }
    stack.push(pkg_name);

    // mark the start of analysis
    debug!(
        "analyzing manifest of package {} at {}",
        package.name,
        root.to_string_lossy()
    );

    // collect named addresses
    let mut named_addresses = BTreeMap::new();
    match manifest.addresses {
        None => (),
        Some(decls) => {
            for (addr_name, addr_config) in decls {
                let addr_val = match addr_config {
                    None => PkgNamedAddr::Unset,
                    Some(a) => PkgNamedAddr::Fixed(a),
                };
                named_addresses.insert(addr_name.to_string(), addr_val);
            }
        },
    }
    match manifest.dev_address_assignments {
        None => (),
        Some(decls) => {
            for (addr_name, addr_val) in decls {
                match named_addresses.get_mut(addr_name.as_str()) {
                    None => bail!(
                        "unrecognized dev assignment for named address {} in package {}",
                        addr_name,
                        package.name
                    ),
                    Some(existing) => match existing {
                        PkgNamedAddr::Unset => {
                            *existing = PkgNamedAddr::Devel(addr_val);
                        },
                        PkgNamedAddr::Devel(_) => panic!(
                            "unexpected dev assignment for named address {} in package {}",
                            addr_name, package.name
                        ),
                        PkgNamedAddr::Fixed(_) => bail!(
                            "dev assignment for named address {} with fixed value in package {}",
                            addr_name,
                            package.name
                        ),
                    },
                }
            }
        },
    }

    // analyze its dependencies
    for (dep_name, dep_info) in dependencies.into_iter().chain(dev_dependencies) {
        if dep_info.node_info.is_some() {
            bail!("on-chain dependency is not supported yet: {}", dep_name);
        }

        // build the information
        let dep_location = match dep_info.git_info.as_ref() {
            None => {
                let dep_path = if dep_info.local.is_absolute() {
                    dep_info.local.clone()
                } else {
                    root.join(&dep_info.local).canonicalize()?
                };
                PkgLocation::Local { path: dep_path }
            },
            Some(git_info) => {
                let dep_path = if git_info.download_to.is_absolute() {
                    git_info.download_to.clone()
                } else {
                    root.join(&git_info.download_to).canonicalize()?
                };
                PkgLocation::Remote {
                    url: git_info.git_url.to_string(),
                    rev: git_info.git_rev.to_string(),
                    subdir: git_info.subdir.clone(),
                    download_to: dep_path,
                }
            },
        };

        // check if we have analyzed this dependency
        let name = dep_name.to_string();
        let optional_version = dep_info.version.as_ref().map(|v| (*v).into());

        match analyzed_pkgs.get(&name) {
            None => (),
            Some(manifest) => {
                // confirm that it is a match
                if dep_location.path() != manifest.path {
                    bail!(
                        "location mismatch of dependency {}: declared {}, analyzed {}",
                        name,
                        dep_location.path().to_string_lossy(),
                        manifest.path.to_string_lossy()
                    );
                }
                match optional_version.as_ref() {
                    None => (),
                    Some(v) => {
                        if v != &manifest.version {
                            bail!(
                                "version mismatch of dependency {}: declared {}, analyzed {}",
                                name,
                                v,
                                manifest.version,
                            );
                        }
                    },
                }

                // we have already analyzed this dependency
                continue;
            },
        }

        // download the dependency first (if it is a remote one)
        if matches!(dep_location, PkgLocation::Remote { .. }) {
            ResolutionGraph::download_and_update_with_lock(
                dep_name,
                &dep_info,
                skip_deps_update,
                &mut std::io::stdout(),
            )?;
        }

        // recursively analyze the dependency
        analyze_package_manifest(
            dep_location,
            Some(name),
            optional_version,
            analyzed_pkgs,
            stack,
            skip_deps_update,
        )?;
    }

    // mark that we have analyzed this manifest
    let pkg_name = stack
        .pop()
        .unwrap_or_else(|| panic!("expect a package on top of stack"));
    assert_eq!(pkg_name, package.name.as_str());

    let exists = analyzed_pkgs.insert(pkg_name.clone(), PkgManifest {
        name: pkg_name.clone(),
        path: root,
        version: pkg_version,
        named_addresses,
    });
    if exists.is_some() {
        panic!("package {} is analyzed twice", package.name);
    }
    Ok(pkg_name)
}

/// Resolve the dependency relation in the whole project
pub fn resolve(paths: Vec<PathBuf>, skip_deps_update: bool) -> Result<Project> {
    let mut analyzed_pkgs = BTreeMap::new();

    // collect packages
    let mut primary_pkgs = BTreeSet::new();
    for path in paths {
        let mut stack = vec![];
        let name = analyze_package_manifest(
            PkgLocation::Local { path },
            None,
            None,
            &mut analyzed_pkgs,
            &mut stack,
            skip_deps_update,
        )?;
        assert!(stack.is_empty());
        primary_pkgs.insert(name);
    }
    debug!(
        "found {} package(s), out of which {} are primary",
        analyzed_pkgs.len(),
        primary_pkgs.len()
    );

    // consolidate named addresses
    let mut named_addresses = BTreeMap::new();
    for pkg in analyzed_pkgs.values() {
        for (addr_name, addr_val) in &pkg.named_addresses {
            match named_addresses.get_mut(addr_name) {
                None => {
                    named_addresses.insert(addr_name.clone(), *addr_val);
                },
                Some(existing) => match (*existing, *addr_val) {
                    (PkgNamedAddr::Unset, PkgNamedAddr::Unset) => (),
                    (PkgNamedAddr::Unset, PkgNamedAddr::Devel(a)) => {
                        *existing = PkgNamedAddr::Devel(a);
                    },
                    (PkgNamedAddr::Devel(_), PkgNamedAddr::Unset) => (),
                    (PkgNamedAddr::Devel(a1), PkgNamedAddr::Devel(a2)) => {
                        if a1 != a2 {
                            bail!(
                                "conflicting dev assignment for named address: {}",
                                addr_name
                            );
                        }
                    },
                    (PkgNamedAddr::Fixed(a1), PkgNamedAddr::Fixed(a2)) => {
                        if a1 != a2 {
                            bail!("conflicting assignment for named address: {}", addr_name);
                        }
                    },
                    (PkgNamedAddr::Unset, PkgNamedAddr::Fixed(_))
                    | (PkgNamedAddr::Devel(_), PkgNamedAddr::Fixed(_))
                    | (PkgNamedAddr::Fixed(_), PkgNamedAddr::Devel(_))
                    | (PkgNamedAddr::Fixed(_), PkgNamedAddr::Unset) => {
                        bail!("conflicting named address declaration: {}", addr_name);
                    },
                },
            }
        }
    }
    debug!(
        "{} named addresses found and consolidated",
        named_addresses.len()
    );

    // done
    let pkgs = analyzed_pkgs
        .into_iter()
        .map(|(k, v)| {
            let is_primary = primary_pkgs.contains(&k);
            (k, (v, is_primary))
        })
        .collect();

    Ok(Project {
        pkgs,
        named_addresses,
    })
}
