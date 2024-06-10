use crate::{
    common::{Account, Project},
    package,
    simulator::{AddressNamespace, Simulator},
};
use anyhow::{anyhow, bail, Result};
use aptos_crypto::{ed25519::Ed25519PrivateKey, HashValue, PrivateKey, Uniform};
use aptos_types::transaction::authenticator::AuthenticationKey;
use log::{debug, error, info};
use move_binary_format::{access::ScriptAccess, file_format::SignatureToken};
use move_compiler::compiled_unit::CompiledUnit;
use move_core_types::{account_address::AccountAddress, transaction_argument::TransactionArgument};
use move_package::compilation::compiled_package::{CompiledPackage, CompiledUnitWithSource};
use rand::rngs::OsRng;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};
use tempfile::TempDir;

const ACCOUNT_INITIAL_FUND_FOR_NUMBER_OF_TRANSACTIONS: u64 = 1000;

/// Provision the simulator with the project
pub fn provision_simulator(simulator: &mut Simulator, project: Project) -> Result<()> {
    let Project {
        pkgs,
        named_accounts,
        language,
    } = project;

    // pre-compile packages to get compiled metadata
    info!("pre-compiling packages");
    let compiled_pkgs: Vec<_> = pkgs
        .iter()
        .map(|(manifest, _)| package::build(manifest, &named_accounts, language, false))
        .collect::<Result<_>>()?;

    // populate accounts for project profiles
    info!("populating project accounts");
    let mut num_accounts = 0;
    for (name, account) in named_accounts {
        match account {
            Account::Ref(addr) => {
                simulator.add_address(name, addr)?;
            },
            Account::Owned(key) => {
                simulator.register_account(
                    name.clone(),
                    key.clone(),
                    Some(ACCOUNT_INITIAL_FUND_FOR_NUMBER_OF_TRANSACTIONS),
                )?;
                num_accounts += 1;
            },
        }
    }

    // now publish all packages in this project
    info!("publishing packages");
    let mut num_published = 0;

    // publish packages in the given order
    for ((manifest, _), compiled) in pkgs.into_iter().zip(compiled_pkgs) {
        let CompiledPackage {
            compiled_package_info,
            root_compiled_units,
            ..
        } = compiled;

        // derive sender account and also collect executable scripts
        let mut accounts = BTreeSet::new();
        for CompiledUnitWithSource { unit, source_path } in root_compiled_units {
            match unit {
                CompiledUnit::Module(module) => {
                    accounts.insert(module.address);
                },
                CompiledUnit::Script(script) => {
                    let file_name = source_path
                        .file_name()
                        .ok_or_else(|| anyhow!("no filename for script"))?
                        .to_str()
                        .ok_or_else(|| anyhow!("non-ASCII filename for script"))?;
                    let script_name = match file_name
                        .strip_prefix("script_")
                        .and_then(|n| n.strip_suffix(".move"))
                    {
                        None => bail!(
                            "filename does not follow the convention of `script_<name>.move`: {}",
                            file_name
                        ),
                        Some(n) => n.to_string(),
                    };
                    simulator.add_script(script_name, script.script)?;
                },
            }
        }

        if accounts.is_empty() {
            // no modules to publish, skip this package
            continue;
        }
        let mut iter = accounts.into_iter();
        let sender_addr = match iter.next() {
            None => {
                // no modules to publish, skip this package
                continue;
            },
            Some(addr) => {
                if iter.next().is_some() {
                    bail!("more than one addresses identified to publish all modules");
                }
                addr.into_inner()
            },
        };

        // only publish packages for which we have a key
        let sender_name = match simulator
            .lookup_namespace_by_address(&sender_addr)
            .unwrap_or_else(|| {
                panic!(
                    "name associated with address {}",
                    sender_addr.to_standard_string(),
                )
            }) {
            AddressNamespace::Ref(_) => {
                debug!(
                    "skipping package {} to be published at {}",
                    manifest.name,
                    sender_addr.to_standard_string(),
                );
                continue;
            },
            AddressNamespace::Owned(name) => name.to_string(),
        };

        // collect named address
        let mut named_addresses = BTreeMap::new();
        for (name, addr) in compiled_package_info
            .address_alias_instantiation
            .into_iter()
        {
            named_addresses.insert(name.to_string(), addr);
        }

        // publish the package
        simulator.publish_package(
            &manifest.name,
            &manifest.path,
            &sender_name,
            &named_addresses,
            language,
        )?;
        debug!(
            "package {} is published at {}",
            manifest.name,
            sender_addr.to_standard_string()
        );
        num_published += 1;
    }

    // done with the provision
    info!(
        "simulator provisioned with {} accounts and {} packages",
        num_accounts, num_published
    );
    Ok(())
}

/// One step of execution in a runbook
#[derive(Serialize, Deserialize)]
struct Step {
    /// Script to execute
    script: String,
    /// Signer of the transaction
    signer: String,
    /// Arguments for the transaction
    params: Vec<Value>,
    /// Expected console output
    #[serde(default)]
    expect: Vec<String>,
    /// Whether this step should abort
    #[serde(default)]
    aborts: bool,
}

#[derive(Serialize)]
struct StepHash(HashValue);

impl<'de> Deserialize<'de> for StepHash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex = <&str>::deserialize(deserializer)?;
        let hash = HashValue::from_hex(hex.strip_prefix("0x").unwrap_or(hex))
            .map_err(serde::de::Error::custom)?;
        Ok(StepHash(hash))
    }
}

#[derive(Serialize, Deserialize)]
struct StepSummary {
    transaction_hash: StepHash,
    gas_used: u64,
    gas_unit_price: u64,
    sender: AccountAddress,
    success: bool,
    version: u64,
    vm_status: String,
}

#[derive(Serialize, Deserialize)]
struct StepResponse {
    #[serde(rename = "Result")]
    result: StepSummary,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum StepOrComment {
    Step(Step),
    Comment {
        #[serde(rename = "//")]
        comments: String,
    },
}

/// The runbook (unvalidated)
#[derive(Serialize, Deserialize)]
struct Runbook(Vec<StepOrComment>);

/// Entrypoint for executing a runbook
pub fn execute_runbook(simulator: &mut Simulator, runbook_path: &Path) -> Result<()> {
    let mut pending_accounts = BTreeMap::new();

    info!("executing runbook at {}", runbook_path.to_string_lossy());
    let book: Runbook = serde_json::from_str(&fs::read_to_string(runbook_path)?)?;

    let mut counter_case = 0;
    let mut counter_step = 0;
    for item in book.0 {
        let step = match item {
            StepOrComment::Comment { comments } => {
                counter_case += 1;
                counter_step = 0;
                info!("==== case {}: {} ====", counter_case, comments);
                continue;
            },
            StepOrComment::Step(s) => s,
        };
        counter_step += 1;

        let Step {
            script,
            signer,
            params,
            expect,
            aborts,
        } = step;
        info!(
            "step {}: {} [{}] {}",
            counter_step,
            script,
            signer,
            params
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );

        // get script and deserialize it script
        let compiled_script = simulator.get_script(&script)?;
        let mut bytes = vec![];
        compiled_script.serialize(&mut bytes)?;

        // parse and validate arguments
        let entry_sig = compiled_script.signature_at(compiled_script.parameters);
        let mut entry_sig_iter = entry_sig.0.iter();
        if entry_sig.len() == params.len() + 1 {
            if !matches!(entry_sig_iter.next().unwrap(), SignatureToken::Signer) {
                bail!("expect signer for the first type parameter of a script function");
            }
        } else if entry_sig.len() != params.len() {
            bail!("wrong number of parameters");
        }

        // parse arguments
        let mut parsed_args = vec![];
        for (param, token) in params.into_iter().zip(entry_sig_iter) {
            let arg = match (param, token) {
                (Value::Bool(v), SignatureToken::Bool) => TransactionArgument::Bool(v),
                (Value::Number(v), SignatureToken::U8) => {
                    TransactionArgument::U8(v.as_str().parse()?)
                },
                (Value::Number(v), SignatureToken::U16) => {
                    TransactionArgument::U16(v.as_str().parse()?)
                },
                (Value::Number(v), SignatureToken::U32) => {
                    TransactionArgument::U32(v.as_str().parse()?)
                },
                (Value::Number(v), SignatureToken::U64) => {
                    TransactionArgument::U64(v.as_str().parse()?)
                },
                (Value::Number(v), SignatureToken::U128) => {
                    TransactionArgument::U128(v.as_str().parse()?)
                },
                (Value::Number(v), SignatureToken::U256) => {
                    TransactionArgument::U256(v.as_str().parse()?)
                },
                (Value::String(v), SignatureToken::Vector(e))
                    if matches!(e.as_ref(), SignatureToken::U8) =>
                {
                    TransactionArgument::U8Vector(v.into_bytes())
                },
                (Value::String(v), SignatureToken::Address) => {
                    let address = match v.strip_prefix('@') {
                        None => v.parse()?,
                        Some(name) => {
                            let addr = match simulator.get_address(name) {
                                None => {
                                    let key = pending_accounts
                                        .entry(name.to_string())
                                        .or_insert_with(|| Ed25519PrivateKey::generate(&mut OsRng));
                                    AuthenticationKey::ed25519(&key.public_key()).account_address()
                                },
                                Some(addr) => addr,
                            };
                            debug!("Arg: @{} => {}", name, addr.to_standard_string());
                            addr
                        },
                    };
                    TransactionArgument::Address(address)
                },
                (p, _) => bail!("invalid argument {}", p),
            };
            parsed_args.push(arg);
        }

        // check whether we need to populate the signer account
        let signer = match signer.strip_prefix('@') {
            None => bail!("signer must be a named account prefixed with `@`"),
            Some(name) => {
                let addr = match simulator.get_address(name) {
                    None => {
                        let key = pending_accounts
                            .remove(name)
                            .unwrap_or_else(|| Ed25519PrivateKey::generate(&mut OsRng));
                        simulator.register_account(
                            name.to_string(),
                            key,
                            Some(ACCOUNT_INITIAL_FUND_FOR_NUMBER_OF_TRANSACTIONS),
                        )?
                    },
                    Some(addr) => addr,
                };
                debug!("Signer: @{} => {}", name, addr.to_standard_string());
                name
            },
        };

        // save the serialized script as a file
        let tmp = TempDir::new()?;
        let exec_path = tmp.path().join("executable.mv");
        fs::write(&exec_path, bytes)?;

        // execute the script (first in simulate mode)
        let (success, stdout) = simulator.run_script(signer, &exec_path, &parsed_args, true)?;
        if !success {
            bail!(
                "script simulation failed at case {} step {}",
                counter_case,
                counter_step,
            );
        }

        // analyze the output
        let mut debugs = vec![];
        let mut result = vec![];
        for line in stdout.iter().map(|l| l.as_str()) {
            if !result.is_empty() {
                // already in result capturing mode
                result.push(line);
            } else if line == "{" {
                // mark the start of result block
                result.push(line);
            } else if let Some(msg) = line.strip_prefix("[debug] ") {
                // capture debug items
                debugs.push(msg);
            }
        }

        // extract the result
        let response: StepResponse = serde_json::from_str(&result.join("\n"))?;
        match (aborts, response.result.success) {
            (true, true) => bail!("expect failure while transaction executed"),
            (false, false) => bail!("expect success while transaction failed"),
            _ => (),
        }

        // cross-check the debug messages
        if debugs.len() != expect.len() {
            error!("debug messages received:");
            for item in debugs {
                error!("  {}", item);
            }
            bail!("output does not match with expectation");
        }
        for (index, (message, expected)) in debugs.into_iter().zip(expect).enumerate() {
            let remapped = match expected.strip_prefix('@') {
                None => expected,
                Some(name) => {
                    if name.starts_with("0x") {
                        expected
                    } else {
                        let addr = simulator
                            .get_address(name)
                            .ok_or_else(|| anyhow!("no such named address: {}", name))?;
                        format!("@{}", addr.to_standard_string())
                    }
                },
            };
            if message != remapped.as_str() {
                bail!("output mismatch at line {}: {}", index, message);
            }
        }

        // execute the script (now in commit mode)
        let (success, _) = simulator.run_script(signer, &exec_path, &parsed_args, false)?;
        match (aborts, success) {
            (true, true) => bail!(
                "expect script execution to fail at case {} step {} but passed",
                counter_case,
                counter_step
            ),
            (false, false) => bail!(
                "expect script execution to pass at case {} step {} but failed",
                counter_case,
                counter_step
            ),
            _ => (),
        }

        // clean-up
        tmp.close()?;
    }
    Ok(())
}
