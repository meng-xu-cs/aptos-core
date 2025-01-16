use crate::{
    common::{Account, LanguageSetting},
    deps::{PkgManifest, PkgNamedAddr},
    simulator::{move_format, move_gen_docs, move_unit_test},
    utils,
};
use anyhow::{bail, Result};
use aptos_framework::{BuildOptions, BuiltPackage};
use move_core_types::account_address::AccountAddress;
use move_package::CompilerConfig;
use std::{collections::BTreeMap, path::Path};

fn collect_named_addresses(
    pkg: &PkgManifest,
    named_accounts: &BTreeMap<String, Account>,
    mapping: &mut BTreeMap<String, AccountAddress>,
) -> Result<()> {
    // collect the package itself
    for (name, addr) in &pkg.named_addresses {
        match addr {
            PkgNamedAddr::Fixed(_) => continue,
            PkgNamedAddr::Unset | PkgNamedAddr::Devel(_) => (),
        }
        match named_accounts.get(name) {
            None => bail!("named address not assigned: {}", name),
            Some(account) => {
                let address = account.address();
                if let Some(existing) = mapping.get(name) {
                    if *existing != address {
                        panic!("conflicting named address assignment: {}", name);
                    }
                } else {
                    mapping.insert(name.clone(), address);
                }
            },
        }
    }

    // collect the dependencies
    for dep in pkg.deps.values() {
        collect_named_addresses(dep, named_accounts, mapping)?;
    }

    // done
    Ok(())
}

pub fn build(
    pkg: &PkgManifest,
    named_accounts: &BTreeMap<String, Account>,
    language: LanguageSetting,
    for_test: bool,
) -> Result<BuiltPackage> {
    // collect assigned addresses
    let mut named_addresses = BTreeMap::new();
    collect_named_addresses(pkg, named_accounts, &mut named_addresses)?;

    // fill the build options
    let CompilerConfig {
        bytecode_version,
        language_version,
        compiler_version,
        known_attributes,
        skip_attribute_checks,
        experiments,
    } = language.derive_compilation_config();

    let options = BuildOptions {
        dev: for_test,
        check_test_code: for_test,
        named_addresses,
        skip_fetch_latest_git_deps: true,
        bytecode_version,
        compiler_version,
        language_version,
        known_attributes,
        skip_attribute_checks,
        experiments,
        // following a minimal config for the rest of the options
        with_abis: false,
        with_docs: false,
        with_srcs: false,
        with_source_maps: false,
        with_error_map: false,
        install_dir: None,
        override_std: None,
        docgen_options: None,
    };

    // build the package
    // HACK: silence logging in compilation
    let package_built =
        utils::with_logging_disabled(|| BuiltPackage::build(pkg.path.clone(), options))?;
    Ok(package_built)
}

pub fn exec_unit_test(
    pkg: &PkgManifest,
    named_accounts: &BTreeMap<String, Account>,
    language: LanguageSetting,
    filter: Option<&str>,
) -> Result<()> {
    // collect assigned addresses
    let mut named_addresses = BTreeMap::new();
    collect_named_addresses(pkg, named_accounts, &mut named_addresses)?;

    // TODO: as a shortcut, currently we call the cli directly, call API instead
    if !move_unit_test(&pkg.path, &named_addresses, language, filter)? {
        bail!("unit test failed on package {}", pkg.name);
    }
    Ok(())
}

pub fn format_code(pkg: &PkgManifest, config: Option<&Path>) -> Result<()> {
    if !move_format(&pkg.path, config)? {
        bail!("code formatting failed on package {}", pkg.name);
    }
    Ok(())
}

pub fn gen_docs(
    pkg: &PkgManifest,
    named_accounts: &BTreeMap<String, Account>,
    language: LanguageSetting,
) -> Result<()> {
    // collect assigned addresses
    let mut named_addresses = BTreeMap::new();
    collect_named_addresses(pkg, named_accounts, &mut named_addresses)?;

    // TODO: as a shortcut, currently we call the cli directly, call API instead
    if !move_gen_docs(&pkg.path, &named_addresses, language)? {
        bail!("document generation failed on package {}", pkg.name);
    }
    Ok(())
}
