use crate::{
    common::{Account, LanguageSetting, PkgDeclaration},
    Project,
};
use anyhow::{anyhow, bail, Result};
use aptos_crypto::{ed25519::Ed25519PrivateKey, Uniform};
use aptos_framework::{
    natives::code::{ModuleMetadata, MoveOption, PackageDep, PackageMetadata, UpgradePolicy},
    zip_metadata_str, UPGRADE_POLICY_CUSTOM_FIELD,
};
use move_compiler::compiled_unit::CompiledUnit;
use move_core_types::account_address::AccountAddress;
use move_package::{
    compilation::compiled_package::CompiledPackage,
    resolution::resolution_graph::ResolutionGraph,
    source_package::{
        layout::SourcePackageLayout,
        manifest_parser::parse_move_manifest_from_file,
        parsed_manifest::{SourceManifest, Version},
    },
    BuildConfig,
};
use move_symbol_pool::Symbol;
use petgraph::{algo::toposort, graph::DiGraph};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Display, Formatter},
    fs, io,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

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
#[derive(Eq, PartialEq, Clone)]
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

impl Display for PkgNamedAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unset => write!(f, "_"),
            Self::Devel(addr) => write!(f, "_{}_", addr),
            Self::Fixed(addr) => write!(f, "{}", addr),
        }
    }
}

/// Manifest of the package being audited
#[derive(Clone)]
pub struct PkgManifest {
    pub name: String,
    pub path: PathBuf,
    pub version: PkgVersion,
    pub deps: BTreeMap<String, PkgManifest>,
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

    // mark the start of analysis
    log::debug!(
        "{}+ package manifest analysis: {}",
        "  ".repeat(stack.len()),
        package.name,
    );

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
            log::debug!(
                "{}- package manifest analysis: {} (cached)",
                "  ".repeat(stack.len()),
                package.name,
            );
            return Ok(pkg_name);
        },
    }

    // ensure that there are no cyclic dependencies on the package level
    if stack.contains(&pkg_name) {
        bail!("cyclic dependency on package {}", pkg_name);
    }
    stack.push(pkg_name);

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
                        "unrecognized dev assignment for named address '{}' in package '{}'",
                        addr_name,
                        package.name
                    ),
                    Some(existing) => match existing {
                        PkgNamedAddr::Unset => {
                            *existing = PkgNamedAddr::Devel(addr_val);
                        },
                        PkgNamedAddr::Devel(_) => unreachable!(
                            "unexpected dev assignment for named address '{}' in package '{}'",
                            addr_name, package.name
                        ),
                        PkgNamedAddr::Fixed(fixed_addr) => {
                            // NOTE: it is weird to see a fixed address being
                            // re-assigned in the dev-address part. It might be
                            // okay if they are assigned the same value, and it
                            // is definitely weird if they are assigned to
                            // different values.
                            if fixed_addr != &addr_val {
                                log::warn!(
                                    "dev assignment for named address '{}' is different from \
                                    the fixed assignment in package '{}'",
                                    addr_name,
                                    package.name
                                );
                            }
                        },
                    },
                }
            }
        },
    }

    // analyze package dependencies
    let mut dep_set = BTreeSet::new();
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
                if dep_location.path() != manifest.path {
                    // HACK: special treatment for Aptos framework packages due
                    // to the mirror repository: https://github.com/aptos-labs/aptos-framework
                    if !matches!(
                        name.as_str(),
                        "MoveStdlib"
                            | "AptosStdlib"
                            | "AptosToken"
                            | "AptosTokenObjects"
                            | "AptosFramework"
                    ) {
                        bail!(
                            "location mismatch of dependency {}: declared {}, analyzed {}",
                            name,
                            dep_location.path().to_string_lossy(),
                            manifest.path.to_string_lossy()
                        );
                    }
                }

                // we have already analyzed this dependency
                if !dep_set.insert(name) {
                    bail!(
                        "dependency {} is declared more than once in {}",
                        dep_name,
                        package.name
                    );
                }
                continue;
            },
        }

        // download the dependency first (if it is a remote one)
        if matches!(dep_location, PkgLocation::Remote { .. }) {
            ResolutionGraph::download_and_update_with_lock(
                dep_name,
                &dep_info,
                skip_deps_update,
                &mut io::stdout(),
            )?;
        }

        // recursively analyze the dependency
        let name = analyze_package_manifest(
            dep_location,
            Some(name),
            optional_version,
            analyzed_pkgs,
            stack,
            skip_deps_update,
        )?;
        if !dep_set.insert(name) {
            bail!(
                "dependency {} is declared more than once in {}",
                dep_name,
                package.name
            );
        }
    }

    // mark that we have analyzed this manifest
    let pkg_name = stack
        .pop()
        .unwrap_or_else(|| panic!("expect a package on top of stack"));
    assert_eq!(pkg_name, package.name.as_str());

    // duplicate the manifests
    let mut deps = BTreeMap::new();
    for name in dep_set {
        let manifest = analyzed_pkgs.get(&name).expect("manifest");
        deps.insert(name, manifest.clone());
    }

    // construct manifest
    let exists = analyzed_pkgs.insert(pkg_name.clone(), PkgManifest {
        name: pkg_name.clone(),
        path: root,
        version: pkg_version,
        deps,
        named_addresses,
    });
    if exists.is_some() {
        panic!("package {} is analyzed twice", package.name);
    }

    // mark the end of the analysis
    log::debug!(
        "{}- package manifest analysis: {} (new)",
        "  ".repeat(stack.len()),
        package.name,
    );
    Ok(pkg_name)
}

/// Resolve the dependency relation in the whole project
pub fn resolve(
    path: &Path,
    language: LanguageSetting,
    address_aliases: BTreeSet<BTreeSet<String>>,
    skip_deps_update: bool,
) -> Result<Project> {
    let base = path.canonicalize()?;

    // find move packages within the project directory
    let mut pkgs = vec![];
    for entry in WalkDir::new(base) {
        let entry = entry?;
        let mut entry_path = entry.into_path();
        if entry_path.file_name().expect("filename") == "Move.toml" {
            // skip if this package is intended to be published dynamically
            let content = fs::read_to_string(&entry_path)?;
            if content
                .lines()
                .next()
                .map_or(false, |l| l.starts_with("#[x] dynamic"))
            {
                continue;
            }
            assert!(entry_path.pop());
            pkgs.push(entry_path);
        }
    }

    // collect packages
    let mut analyzed_pkgs = BTreeMap::new();
    let mut primary_pkgs = BTreeSet::new();
    for path in pkgs {
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
    log::info!(
        "found {} package(s), out of which {} are primary",
        analyzed_pkgs.len(),
        primary_pkgs.len()
    );

    // consolidate named addresses
    let mut consolidated = BTreeMap::new();
    for pkg in analyzed_pkgs.values() {
        for (addr_name, addr_val) in &pkg.named_addresses {
            match consolidated.get_mut(addr_name) {
                None => {
                    consolidated.insert(addr_name.clone(), *addr_val);
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
    log::debug!(
        "{} named addresses found and consolidated",
        consolidated.len()
    );

    // unpack the consolidation and assign random addresses for unset ones
    let mut named_accounts: BTreeMap<_, Account> = BTreeMap::new();
    for (key, val) in consolidated {
        // check for alias (if exists)
        let mut alias = None;
        for group in &address_aliases {
            if !group.contains(&key) {
                continue;
            }
            for item in group {
                match named_accounts.get(item) {
                    None => continue,
                    Some(a) => {
                        alias = Some(a.address());
                        break;
                    },
                }
            }
            if alias.is_some() {
                break;
            }
        }

        // handle actual assignments
        let account = match val {
            PkgNamedAddr::Fixed(addr) => {
                if matches!(alias, Some(a) if a != addr) {
                    bail!("invalid alias declaration: {}", key);
                }
                Account::Ref(addr)
            },
            PkgNamedAddr::Devel(_) | PkgNamedAddr::Unset => match alias {
                None => Account::Owned(Ed25519PrivateKey::generate(&mut OsRng)),
                Some(a) => Account::Ref(a),
            },
        };
        named_accounts.insert(key, account);
    }

    // additionally check that all aliases are assigned
    for group in address_aliases {
        for name in group {
            if !named_accounts.contains_key(&name) {
                bail!("unused name in address alias declaration: {}", name);
            }
        }
    }

    // build a dependency graph out of these packages
    let mut graph = DiGraph::new();
    let mut index_mapping = BTreeMap::new();
    for name in analyzed_pkgs.keys() {
        let index = graph.add_node(name.clone());
        index_mapping.insert(name.clone(), index);
    }
    for (name, pkg) in &analyzed_pkgs {
        let dst = *index_mapping.get(name).expect("dst node");
        for dep in pkg.deps.keys() {
            let src = *index_mapping.get(dep).expect("src node");
            graph.add_edge(src, dst, ());
        }
    }

    // topologically sort the dependency graph
    let mut pkgs = vec![];
    match toposort(&graph, None) {
        Ok(nodes) => {
            for node in nodes {
                let key = graph.node_weight(node).expect("node");
                let pkg = analyzed_pkgs
                    .remove(key)
                    .unwrap_or_else(|| panic!("expect package with name {key}"));
                let is_primary = primary_pkgs.contains(key);
                let is_framework = matches!(
                    key.as_str(),
                    "MoveStdlib"
                        | "AptosStdlib"
                        | "AptosFramework"
                        | "AptosToken"
                        | "AptosTokenObjects"
                );
                let decl = match (is_primary, is_framework) {
                    (true, true) => {
                        bail!("analyzing Aptos framework package '{key}' is not supported")
                    },
                    (true, false) => PkgDeclaration::Primary(pkg),
                    (false, true) => PkgDeclaration::Framework(pkg),
                    (false, false) => PkgDeclaration::Dependency(pkg),
                };
                pkgs.push(decl);
            }
        },
        Err(cycle) => {
            bail!(
                "unexpected cyclic dependency in packages: {}",
                graph
                    .node_weight(cycle.node_id())
                    .map_or("<unknown>", |e| e.as_str())
            );
        },
    }

    // instantiate templates in the Move source code in the packages
    for pkg in &pkgs {
        let mut stack = vec![];
        instantiate_all(
            &language,
            &pkg.as_manifest().path,
            &named_accounts,
            &mut stack,
        )?;
        assert!(stack.is_empty());
    }

    // done
    Ok(Project {
        pkgs,
        named_accounts,
        language,
    })
}

/// Instantiate all Move files under this directory
fn instantiate_all(
    language: &LanguageSetting,
    dir_path: &Path,
    named_accounts: &BTreeMap<String, Account>,
    publishing_stack: &mut Vec<(String, AccountAddress)>,
) -> Result<()> {
    for entry in WalkDir::new(dir_path) {
        let entry = entry?;
        let entry_path = entry.path();
        if entry_path.extension().map_or(false, |ext| ext == "move") {
            instantiate_one(language, entry_path, named_accounts, publishing_stack)?;
        }
    }
    Ok(())
}

enum PendingLine<'a> {
    None,
    Meta(&'a str),
    Code(&'a str),
}

/// Instantiate one Move source code file if applicable
fn instantiate_one(
    language: &LanguageSetting,
    file_path: &Path,
    named_accounts: &BTreeMap<String, Account>,
    publishing_stack: &mut Vec<(String, AccountAddress)>,
) -> Result<()> {
    let content = fs::read_to_string(file_path)?;
    if !content.starts_with("//[x]") {
        // do nothing if no directives found
        return Ok(());
    }

    // instantiate the content
    let mut instantiated = vec![];
    let mut probing = true;
    let mut dyn_pkgs = BTreeMap::new();
    let mut pending = PendingLine::None;

    for line in content.lines() {
        // scan for dynamic packages first
        if probing {
            match line.strip_prefix("//[x] dynamic: ") {
                None => {
                    // mark the end of the dynamic package probing session
                    probing = false;
                },
                Some(rest) => {
                    let (dyn_name, dyn_meta, dyn_code) = handle_directive_dynamic(
                        language,
                        rest,
                        file_path,
                        named_accounts,
                        publishing_stack,
                    )?;
                    let exists = dyn_pkgs.insert(dyn_name, (dyn_meta, dyn_code));
                    if exists.is_some() {
                        bail!("duplicated dynamic package directive: {}", rest);
                    }

                    instantiated.push(line.to_string());
                    continue;
                },
            }
        }
        assert!(!probing);

        // check if we are about to instantiate
        match pending {
            PendingLine::None => (),
            PendingLine::Meta(name) => {
                if !line.trim().starts_with("let meta = ") {
                    bail!("expect meta definition line, got '{}' instead", line);
                }

                let (meta, _) = dyn_pkgs
                    .get(name)
                    .ok_or_else(|| anyhow!("no such package: {}", name))?;
                instantiated.push(format!("let meta = x\"{}\";", hex::encode_upper(meta)));
                pending = PendingLine::None;
                continue;
            },
            PendingLine::Code(name) => {
                if !line.trim().starts_with("let code = ") {
                    bail!("expect code definition line, got '{}' instead", line);
                }

                let (_, code) = dyn_pkgs
                    .get(name)
                    .ok_or_else(|| anyhow!("no such package: {}", name))?;
                let encoded_code: Vec<_> = code
                    .iter()
                    .map(|c| format!("x\"{}\"", hex::encode_upper(c)))
                    .collect();
                instantiated.push(format!("let code = vector[{}];", encoded_code.join(",")));
                pending = PendingLine::None;
                continue;
            },
        }

        // now need to parse the line
        match line.trim().strip_prefix("//[x] meta: ") {
            None => match line.trim().strip_prefix("//[x] code: ") {
                None => {},
                Some(rest) => {
                    pending = PendingLine::Code(rest);
                },
            },
            Some(rest) => {
                pending = PendingLine::Meta(rest);
            },
        };

        // always save the current line
        instantiated.push(line.to_string());
    }

    // override the original file
    fs::write(file_path, instantiated.join("\n"))?;

    // done
    Ok(())
}

/// Handle the `//[x] dynamic:` directive
fn handle_directive_dynamic(
    language: &LanguageSetting,
    directive: &str,
    file_path: &Path,
    named_accounts: &BTreeMap<String, Account>,
    publishing_stack: &mut Vec<(String, AccountAddress)>,
) -> Result<(String, Vec<u8>, Vec<Vec<u8>>)> {
    let mut params = directive.split_whitespace();

    // probe for dynamic package metadata from directive
    let dyn_id = params
        .next()
        .ok_or_else(|| anyhow!("expect dynamic package id"))?;
    let dyn_path = file_path
        .parent()
        .expect("parent directory")
        .join(
            params
                .next()
                .ok_or_else(|| anyhow!("expect dynamic package path"))?,
        )
        .canonicalize()?;
    let dyn_addr_name = params
        .next()
        .ok_or_else(|| anyhow!("expect dynamic package address name"))?;

    // check if we are publishing to
    // - a resource account (i.e., newly created) or
    // - an existing account (i.e., with signer already there)

    let address = match params.next() {
        None => find_address_in_context(dyn_addr_name, named_accounts, publishing_stack)?,
        Some(dyn_addr_base) => {
            // publishing to a new resource account
            let dyn_addr_seed = params
                .next()
                .ok_or_else(|| anyhow!("expect dynamic package address seed"))?;

            if params.next().is_some() {
                bail!("invalid directive: {}", directive);
            }

            // derive the address
            let base = find_address_in_context(dyn_addr_base, named_accounts, publishing_stack)?;
            let mut content = bcs::to_bytes(&base)?;
            content.extend(dyn_addr_seed.as_bytes());
            content.push(255); // DERIVE_RESOURCE_ACCOUNT_SCHEME
            AccountAddress::from_bytes(Sha3_256::digest(&content))?
        },
    };

    // advance the context
    publishing_stack.push((dyn_addr_name.to_string(), address));
    instantiate_all(language, &dyn_path, named_accounts, publishing_stack)?;

    // compile the new package
    let mut named_addresses = BTreeMap::new();
    for (name, account) in named_accounts {
        named_addresses.insert(name.to_string(), account.address());
    }
    for (name, address) in publishing_stack.iter() {
        named_addresses.insert(name.to_string(), *address);
    }

    let config = BuildConfig {
        dev_mode: false,
        test_mode: false,
        force_recompilation: true,
        generate_move_model: true,
        full_model_generation: false,
        skip_fetch_latest_git_deps: true,
        additional_named_addresses: named_addresses,
        compiler_config: language.derive_compilation_config(),
        ..Default::default()
    };
    let pkg = config.compile_package(&dyn_path, &mut io::stdout())?;

    // derive metadata and code
    let (meta, code) = extract_meta_and_code(&pkg, &dyn_path)?;

    // pop up the context
    publishing_stack
        .pop()
        .expect("publishing stack should not be empty");

    // done
    Ok((dyn_id.to_string(), meta, code))
}

fn find_address_in_context(
    dyn_addr_name: &str,
    named_accounts: &BTreeMap<String, Account>,
    publishing_stack: &[(String, AccountAddress)],
) -> Result<AccountAddress> {
    // first check the stack
    for (name, addr) in publishing_stack.iter().rev() {
        if dyn_addr_name == name {
            return Ok(*addr);
        }
    }
    // then check the named accounts
    named_accounts
        .get(dyn_addr_name)
        .map(|a| a.address())
        .ok_or_else(|| anyhow!("unable to find assigned address for {}", dyn_addr_name))
}

/// Extracts metadata and code, as needed for releasing a package, from the built package.
fn extract_meta_and_code(pkg: &CompiledPackage, src: &Path) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    // deserialize manifest
    let manifest_file = src.join(SourcePackageLayout::Manifest.path());
    let manifest = parse_move_manifest_from_file(&manifest_file)?;

    // extract misc properties
    let upgrade_policy = match manifest
        .package
        .custom_properties
        .get(&Symbol::from(UPGRADE_POLICY_CUSTOM_FIELD))
    {
        None => UpgradePolicy::compat(),
        Some(v) => v.parse()?,
    };
    let source_digest = pkg
        .compiled_package_info
        .source_digest
        .map(|s| s.to_string())
        .unwrap_or_default();
    let bytecode_version = pkg
        .compiled_package_info
        .build_flags
        .compiler_config
        .bytecode_version
        .expect("bytecode version explicitly set");

    // metadata: module
    let mut modules = vec![];
    for module in pkg.root_modules() {
        let name = module.unit.name().to_string();
        let source = vec![];
        let source_map = vec![];
        modules.push(ModuleMetadata {
            name,
            source,
            source_map,
            extension: MoveOption::default(),
        })
    }

    // metadata: dependencies
    let deps = pkg
        .deps_compiled_units
        .iter()
        .filter_map(|(name, unit)| {
            let package_name = name.as_str().to_string();
            let account = match &unit.unit {
                CompiledUnit::Module(m) => AccountAddress::new(m.address.into_bytes()),
                CompiledUnit::Script(_) => return None,
            };
            Some(PackageDep {
                account,
                package_name,
            })
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    // obtain metadata and data
    let meta = PackageMetadata {
        name: manifest.package.name.to_string(),
        upgrade_policy,
        upgrade_number: 0,
        source_digest,
        manifest: zip_metadata_str(&manifest.to_string())?,
        modules,
        deps,
        extension: MoveOption::none(),
    };
    let code = pkg
        .root_modules()
        .map(|unit_with_source| unit_with_source.unit.serialize(Some(bytecode_version)))
        .collect();
    Ok((bcs::to_bytes(&meta)?, code))
}
