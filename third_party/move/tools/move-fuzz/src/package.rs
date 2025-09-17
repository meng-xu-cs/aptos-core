// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    common::Account,
    deps::{PkgManifest, PkgNamedAddr},
    language::LanguageSetting,
    utils,
};
use anyhow::{bail, Result};
use aptos_framework::{BuildOptions, BuiltPackage};
use aptos_gas_schedule::{
    InitialGasSchedule, MiscGasParameters, NativeGasParameters, LATEST_GAS_FEATURE_VERSION,
};
use aptos_types::on_chain_config::{
    aptos_test_feature_flags_genesis, Features, TimedFeaturesBuilder,
};
use aptos_vm::natives;
use move_cli::base::test::{run_move_unit_tests, UnitTestResult};
use move_core_types::account_address::AccountAddress;
use move_package::{BuildConfig, CompilerConfig};
use move_unit_test::UnitTestingConfig;
use move_vm_test_utils::gas_schedule::INITIAL_COST_SCHEDULE;
use std::collections::BTreeMap;

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
                        unreachable!("conflicting named address assignment: {}", name);
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

/// Build a package with the given language settings and named accounts
pub fn build(
    pkg: &PkgManifest,
    named_accounts: &BTreeMap<String, Account>,
    language: LanguageSetting,
    dev_mode: bool,
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
        dev: dev_mode,
        check_test_code: dev_mode,
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

/// Run Move unit tests in the given package
pub fn unit_test(
    pkg: &PkgManifest,
    named_accounts: &BTreeMap<String, Account>,
    language: LanguageSetting,
    test_filter: Option<&str>,
    gas: bool,
    single_thread: bool,
) -> Result<()> {
    // collect assigned addresses
    let mut named_addresses = BTreeMap::new();
    collect_named_addresses(pkg, named_accounts, &mut named_addresses)?;

    // fill the build options
    let build_config = BuildConfig {
        dev_mode: true,
        test_mode: true,
        skip_fetch_latest_git_deps: true,
        additional_named_addresses: named_addresses,
        compiler_config: language.derive_compilation_config(),
        // enable model generation explicitly
        generate_move_model: true,
        full_model_generation: true,
        // following a minimal config for the rest of the options
        override_std: None,
        generate_docs: false,
        generate_abis: false,
        install_dir: None,
        force_recompilation: false,
        fetch_deps_only: true,
    };
    let test_config = UnitTestingConfig {
        filter: test_filter.map(|s| s.to_string()),
        num_threads: if single_thread { 1 } else { num_cpus::get() },
        // values not used at all
        named_address_values: vec![],
        // minimal config for the rest of the options
        list: false,
        dep_files: vec![],
        source_files: vec![],
        ignore_compile_warnings: true,
        report_statistics: false,
        report_storage_on_error: false,
        report_stacktrace_on_abort: true,
        verbose: false,
    };

    // setup gas and natives
    let (cost_table, native_gas, misc_gas) = if gas {
        (
            Some(INITIAL_COST_SCHEDULE.clone()),
            NativeGasParameters::initial(),
            MiscGasParameters::initial(),
        )
    } else {
        (
            None,
            NativeGasParameters::zeros(),
            MiscGasParameters::zeros(),
        )
    };
    let natives = natives::aptos_natives(
        LATEST_GAS_FEATURE_VERSION,
        native_gas,
        misc_gas,
        TimedFeaturesBuilder::enable_all().build(),
        Features::default(),
    );

    // run the tests
    let result = run_move_unit_tests(
        &pkg.path,
        build_config,
        test_config,
        natives,
        aptos_test_feature_flags_genesis(),
        None, // unlimited gas consumption
        cost_table,
        false, // TODO: enable coverage calculation
        &mut std::io::stdout(),
        true,
    )?;

    match result {
        UnitTestResult::Success => Ok(()),
        UnitTestResult::Failure => bail!("Move unit test failed"),
    }
}
