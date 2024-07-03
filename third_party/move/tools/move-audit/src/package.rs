use crate::{
    common::Account,
    config::APTOS_BIN,
    deps::{PkgManifest, PkgNamedAddr},
};
use anyhow::{bail, Result};
use aptos_framework::extended_checks;
use move_core_types::account_address::AccountAddress;
use move_package::{compilation::compiled_package::CompiledPackage, BuildConfig, CompilerConfig};
use std::{collections::BTreeMap, io, process::Command};

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
    for_test: bool,
) -> Result<CompiledPackage> {
    // collect assigned addresses
    let mut named_addresses = BTreeMap::new();
    collect_named_addresses(pkg, named_accounts, &mut named_addresses)?;

    // build the package
    let config = BuildConfig {
        dev_mode: for_test,
        test_mode: for_test,
        skip_fetch_latest_git_deps: true,
        additional_named_addresses: named_addresses,
        compiler_config: CompilerConfig {
            known_attributes: extended_checks::get_all_attribute_names().clone(),
            ..Default::default()
        },
        ..Default::default()
    };
    config.compile_package(&pkg.path, &mut io::stdout())
}

pub fn exec_unit_test(
    pkg: &PkgManifest,
    named_accounts: &BTreeMap<String, Account>,
    compile_only: bool,
) -> Result<()> {
    // use a separate route to compile the packages
    if compile_only {
        build(pkg, named_accounts, true)?;
        return Ok(());
    }

    // collect assigned addresses
    let mut named_addresses = BTreeMap::new();
    collect_named_addresses(pkg, named_accounts, &mut named_addresses)?;

    let named_address_pairs: Vec<_> = named_addresses
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    // NOTE: as a shortcut, call the cli directly
    let status = Command::new(APTOS_BIN.as_path())
        .args([
            "move",
            "test",
            "--skip-fetch-latest-git-deps",
            "--dev",
            "--named-addresses",
        ])
        .arg(named_address_pairs.join(","))
        .current_dir(&pkg.path)
        .spawn()?
        .wait()?;
    if !status.success() {
        bail!("unit test failed on package {}", pkg.name);
    }

    // done
    Ok(())
}
