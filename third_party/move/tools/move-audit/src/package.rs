use crate::{
    config::APTOS_BIN,
    deps::{PkgManifest, PkgNamedAddr},
    testnet::ProfileConfig,
};
use anyhow::{bail, Result};
use move_core_types::account_address::AccountAddress;
use std::{collections::BTreeMap, process::Command};

fn collect_named_addresses(
    pkg: &PkgManifest,
    config: &ProfileConfig,
    mapping: &mut BTreeMap<String, AccountAddress>,
) -> Result<()> {
    // collect the package itself
    for (name, addr) in &pkg.named_addresses {
        match addr {
            PkgNamedAddr::Fixed(_) => continue,
            PkgNamedAddr::Unset | PkgNamedAddr::Devel(_) => (),
        }
        match config.profiles.get(name) {
            None => bail!("named address not assigned: {}", name),
            Some(profile) => {
                if let Some(existing) = mapping.get(name) {
                    if *existing != profile.account {
                        panic!("conflicting named address assignment: {}", name);
                    }
                } else {
                    mapping.insert(name.clone(), profile.account);
                }
            },
        }
    }

    // collect the dependencies
    for dep in pkg.deps.values() {
        collect_named_addresses(dep, config, mapping)?;
    }

    // done
    Ok(())
}

pub fn exec_unit_test(pkg: &PkgManifest, config: &ProfileConfig, compile_only: bool) -> Result<()> {
    // collect assigned addresses
    let mut named_addresses = BTreeMap::new();
    collect_named_addresses(pkg, config, &mut named_addresses)?;

    let named_address_pairs: Vec<_> = named_addresses
        .into_iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    // NOTE: as a shortcut, call the aptos cli directly
    let status = Command::new(APTOS_BIN.as_path())
        .args([
            "move",
            if compile_only { "compile" } else { "test" },
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
