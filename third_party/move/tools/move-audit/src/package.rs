use crate::{
    common::{Account, LanguageSetting},
    deps::{PkgManifest, PkgNamedAddr},
    simulator::{move_format, move_gen_docs, move_unit_test},
};
use anyhow::{bail, Result};
use log::LevelFilter;
use move_core_types::account_address::AccountAddress;
use move_package::{compilation::compiled_package::CompiledPackage, BuildConfig};
use std::{collections::BTreeMap, io, path::Path};

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
) -> Result<CompiledPackage> {
    // collect assigned addresses
    let mut named_addresses = BTreeMap::new();
    collect_named_addresses(pkg, named_accounts, &mut named_addresses)?;

    // build the package
    let config = BuildConfig {
        dev_mode: for_test,
        test_mode: for_test,
        force_recompilation: true,
        generate_move_model: true,
        full_model_generation: for_test,
        skip_fetch_latest_git_deps: true,
        additional_named_addresses: named_addresses,
        compiler_config: language.derive_compilation_config(),
        ..Default::default()
    };

    // HACK: silence logging in compilation
    let log_level = log::max_level();
    log::set_max_level(LevelFilter::Off);
    let compiled_package = config.compile_package(&pkg.path, &mut io::stdout())?;
    log::set_max_level(log_level);

    Ok(compiled_package)
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
