use crate::{
    common::{Account, LanguageSetting},
    subexec::SubExec,
};
use anyhow::{anyhow, bail, Result};
use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey};
use aptos_types::transaction::authenticator::AuthenticationKey;
use lazy_static::lazy_static;
use log::{debug, info};
use move_binary_format::file_format::CompiledScript;
use move_core_types::{account_address::AccountAddress, transaction_argument::TransactionArgument};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, RwLock},
};
use tempfile::TempDir;

/// Disables telemetry
const ENV_APTOS_DISABLE_TELEMETRY: &str = "APTOS_DISABLE_TELEMETRY";

/// Default gas unit price
const DEFAULT_GAS_UNIT_PRICE: u32 = 100;
// TODO(mengxu): kept in sync with aptos_config::global_constants::GAS_UNIT_PRICE

/// Default gas maximum
const DEFAULT_MAX_GAS_AMOUNT: u32 = 2_000_000;
// TODO(mengxu): kept in sync with aptos_config::global_constants::MAX_GAS_AMOUNT

lazy_static! {
    /// Path to the current Aptos CLI
    static ref APTOS_BIN: PathBuf =
        std::env::current_exe()
            .and_then(|p| p.canonicalize())
            .expect("current executable path");
}

/// Whether this is an owned or referred address
pub enum AddressNamespace {
    Ref(BTreeSet<String>),
    Owned(String),
}

/// Configuration for the simulator
struct Config {
    /// use realistic gas setting
    realistic_gas: bool,
}

/// Simulator for local testnet
pub struct Simulator {
    /// simulator config
    config: Config,
    /// temporary working directory
    workdir: TempDir,
    /// the local testnet process in background
    executor: SubExec,
    /// accounts registered
    named_accounts: BTreeMap<String, Account>,
    /// address reverse lookup
    address_lookup: BTreeMap<AccountAddress, AddressNamespace>,
    /// executable scripts
    executables: BTreeMap<String, CompiledScript>,
}

impl Simulator {
    /// Initialize a new simulator
    pub fn new(realistic_gas: bool) -> Result<Self> {
        // always create a fresh temp directory
        let workdir = TempDir::new()?;

        // launch the testnet
        info!("launching local testnet");
        let mut command = Command::new(APTOS_BIN.as_path());
        command
            .args([
                "node",
                "run-local-testnet",
                "--with-faucet",
                "--force-restart",
            ])
            .env(ENV_APTOS_DISABLE_TELEMETRY, "1")
            .current_dir(workdir.path());

        let stderr = Arc::new(RwLock::new(vec![]));
        let executor = SubExec::run(command, None, Some(Arc::clone(&stderr)))?;

        // wait for testnet to be ready
        debug!("waiting for local testnet to initialize");
        let mut next_line = 0;
        'wait: loop {
            let lines = stderr.read().expect("stderr read lock");
            let count = lines.len();
            if count == next_line {
                continue;
            }

            // new content available
            for line in &lines[next_line..count] {
                if line == "Setup is complete, you can now use the localnet!" {
                    break 'wait;
                }
            }
            next_line = count;
        }

        // now we have a new simulator
        info!("local testnet is ready");
        Ok(Self {
            config: Config { realistic_gas },
            workdir,
            executor,
            named_accounts: BTreeMap::new(),
            address_lookup: BTreeMap::new(),
            executables: BTreeMap::new(),
        })
    }

    /// Add a dependency address to the system
    pub fn add_address(&mut self, name: String, address: AccountAddress) -> Result<()> {
        // ensure no duplication
        if self.named_accounts.contains_key(&name) {
            bail!("address already exists: {}", name);
        }

        // add the pair
        if let Some(ns) = self.address_lookup.get_mut(&address) {
            match ns {
                AddressNamespace::Ref(names) => {
                    if !names.insert(name.clone()) {
                        bail!(
                            "duplicated address registration: @{} => {}",
                            name,
                            address.to_standard_string()
                        );
                    }
                },
                AddressNamespace::Owned(..) => bail!(
                    "address cannot be both owned and referred: @{} => {}",
                    name,
                    address.to_standard_string()
                ),
            }
        } else {
            let mut names = BTreeSet::new();
            names.insert(name.clone());
            self.address_lookup
                .insert(address, AddressNamespace::Ref(names));
        }
        self.named_accounts.insert(name, Account::Ref(address));

        // done
        Ok(())
    }

    /// Register a user account and also fund it if requested
    pub fn register_account(
        &mut self,
        name: String,
        key: Ed25519PrivateKey,
        fund_for_num_txns: Option<u64>,
    ) -> Result<AccountAddress> {
        // ensure no duplication
        if self.named_accounts.contains_key(&name) {
            bail!("address already exists: {}", name);
        }

        // register account
        let key_string = format!("0x{}", hex::encode(key.to_bytes()));
        let mut command = Command::new(APTOS_BIN.as_path());
        command
            .args([
                "init",
                "--network",
                "local",
                "--profile",
                &name,
                "--private-key",
                &key_string,
                "--skip-faucet",
                "--assume-yes",
            ])
            .env(ENV_APTOS_DISABLE_TELEMETRY, "1")
            .current_dir(self.workdir.path());
        if !SubExec::invoke(command)? {
            bail!("failed to create account {}", name);
        }
        debug!("account registered: {}", name);

        // fund the account if requested
        match fund_for_num_txns {
            None | Some(0) => (),
            Some(count) => {
                let fund = count * (DEFAULT_MAX_GAS_AMOUNT as u64);
                let mut command = Command::new(APTOS_BIN.as_path());
                command
                    .args([
                        "account",
                        "fund-with-faucet",
                        "--profile",
                        &name,
                        "--account",
                        &name,
                        "--amount",
                        &fund.to_string(),
                    ])
                    .env(ENV_APTOS_DISABLE_TELEMETRY, "1")
                    .current_dir(self.workdir.path());
                if !SubExec::invoke(command)? {
                    bail!("failed to fund account {} with {} tokens", name, fund);
                }
                debug!("account {} is funded with {} tokens", name, fund);
            },
        }

        // add the pair
        let address = AuthenticationKey::ed25519(&key.public_key()).account_address();
        let existing = self
            .address_lookup
            .insert(address, AddressNamespace::Owned(name.clone()));
        if existing.is_some() {
            bail!(
                "duplicated account address registration: @{} => {}",
                name,
                address.to_standard_string()
            );
        }
        self.named_accounts.insert(name, Account::Owned(key));

        // done
        Ok(address)
    }

    /// Lookup address by name
    pub fn get_address(&self, name: &str) -> Option<AccountAddress> {
        self.named_accounts
            .get(name)
            .map(|account| account.address())
    }

    /// Lookup namespace by address
    pub fn lookup_namespace_by_address(
        &self,
        address: &AccountAddress,
    ) -> Option<&AddressNamespace> {
        self.address_lookup.get(address)
    }

    /// Publish a package
    pub fn publish_package(
        &mut self,
        package_name: &str,
        package_path: &Path,
        sender: &str,
        named_addresses: &BTreeMap<String, AccountAddress>,
        language: LanguageSetting,
    ) -> Result<()> {
        let named_address_pairs: Vec<_> = named_addresses
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();

        // command: basics
        let mut command = Command::new(APTOS_BIN.as_path());
        command.args(["move", "publish"]);
        // command: sender
        command.args(["--profile", sender, "--sender-account", sender]);
        // command: gas
        if !self.config.realistic_gas {
            command.args([
                "--gas-unit-price",
                &DEFAULT_GAS_UNIT_PRICE.to_string(),
                "--max-gas",
                &DEFAULT_MAX_GAS_AMOUNT.to_string(),
            ]);
        }
        // command: project
        command
            .arg("--package-dir")
            .arg(package_path)
            .arg("--named-addresses")
            .arg(named_address_pairs.join(","))
            .arg("--skip-fetch-latest-git-deps");
        // command: language
        language.derive_cli_options(&mut command);
        // command: configs
        command.args(["--included-artifacts", "none", "--override-size-check"]);
        // command: misc
        command
            .arg("--assume-yes")
            .env(ENV_APTOS_DISABLE_TELEMETRY, "1")
            .current_dir(self.workdir.path());

        if !SubExec::invoke(command)? {
            bail!("failed to publish package {}", package_name);
        }
        Ok(())
    }

    /// Add a script
    pub fn add_script(&mut self, name: String, script: CompiledScript) -> Result<()> {
        if self.executables.contains_key(&name) {
            bail!("two scripts share the same name: {}", name);
        }
        self.executables.insert(name, script);
        Ok(())
    }

    /// Get a script
    pub fn get_script(&self, name: &str) -> Result<&CompiledScript> {
        self.executables
            .get(name)
            .ok_or_else(|| anyhow!("no such script: {}", name))
    }

    /// Execute a script
    pub fn run_script(
        &self,
        account: &str,
        script_path: &Path,
        script_args: &[TransactionArgument],
        simulate: bool,
    ) -> Result<(bool, Vec<String>)> {
        let typed_args: Vec<_> = script_args
            .iter()
            .map(|arg| match arg {
                TransactionArgument::Bool(v) => format!("bool:{}", v),
                TransactionArgument::U8(v) => format!("u8:{}", v),
                TransactionArgument::U16(v) => format!("u16:{}", v),
                TransactionArgument::U32(v) => format!("u32:{}", v),
                TransactionArgument::U64(v) => format!("u64:{}", v),
                TransactionArgument::U128(v) => format!("u128:{}", v),
                TransactionArgument::U256(v) => format!("u256:{}", v),
                TransactionArgument::Address(v) => format!("address:{}", v.to_standard_string()),
                TransactionArgument::U8Vector(v) => {
                    format!("string:{}", std::str::from_utf8(v).expect("UTF-8 string"))
                },
                TransactionArgument::Serialized(_) => {
                    panic!("serialized transaction argument not supported");
                },
            })
            .collect();

        // command: basics
        let mut command = Command::new(APTOS_BIN.as_path());
        command.args(["move", "run-script"]);
        // command: sender
        command.args(["--profile", account, "--sender-account", account]);
        // command: gas
        if !self.config.realistic_gas {
            command.args([
                "--gas-unit-price",
                &DEFAULT_GAS_UNIT_PRICE.to_string(),
                "--max-gas",
                &DEFAULT_MAX_GAS_AMOUNT.to_string(),
            ]);
        }
        // command: script
        command.arg("--compiled-script-path").arg(script_path);
        if !typed_args.is_empty() {
            command.arg("--args").args(typed_args);
        }
        // command: configs
        if simulate {
            command.arg("--local");
        }
        // command: misc
        command
            .env(ENV_APTOS_DISABLE_TELEMETRY, "1")
            .current_dir(self.workdir.path());
        SubExec::output_stdout(command)
    }

    /// Tear down the simulator
    pub fn destroy(self) -> Result<()> {
        let Self {
            config: _,
            workdir,
            executor,
            named_accounts: _,
            address_lookup: _,
            executables: _,
        } = self;

        executor.interrupt()?;
        workdir.close()?;

        // done with the destruction
        info!("local testnet is shutdown");
        Ok(())
    }
}

/// Shortcut to move function: run unit test
pub fn move_unit_test(
    pkg_dir: &Path,
    named_addresses: &BTreeMap<String, AccountAddress>,
    language: LanguageSetting,
) -> Result<bool> {
    let named_address_pairs: Vec<_> = named_addresses
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    let mut command = Command::new(APTOS_BIN.as_path());
    command.args(["move", "test"]);
    command.args(["--dev", "--skip-fetch-latest-git-deps"]);
    command
        .arg("--named-addresses")
        .arg(named_address_pairs.join(","));
    language.derive_cli_options(&mut command);
    command
        .env(ENV_APTOS_DISABLE_TELEMETRY, "1")
        .current_dir(pkg_dir);

    SubExec::invoke(command)
}

/// Shortcut to move function: generate documents
pub fn move_gen_docs(
    pkg_dir: &Path,
    named_addresses: &BTreeMap<String, AccountAddress>,
    language: LanguageSetting,
) -> Result<bool> {
    let named_address_pairs: Vec<_> = named_addresses
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    let mut command = Command::new(APTOS_BIN.as_path());
    command.args(["move", "document"]);
    command.args(["--dev", "--skip-fetch-latest-git-deps"]);
    command
        .arg("--named-addresses")
        .arg(named_address_pairs.join(","));
    language.derive_cli_options(&mut command);
    command.args(["--include-impl", "--include-specs", "--include-dep-diagram"]);
    command
        .env(ENV_APTOS_DISABLE_TELEMETRY, "1")
        .current_dir(pkg_dir);

    SubExec::invoke(command)
}
