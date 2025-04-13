use crate::{
    common::{Account, Project, TxnArg, TxnArgType, TxnArgTypeWithRef},
    package,
    simulator::{AddressNamespace, Runnable, Simulator},
};
use anyhow::{anyhow, bail, Result};
use aptos_crypto::{ed25519::Ed25519PrivateKey, HashValue, PrivateKey, Uniform};
use aptos_types::transaction::authenticator::AuthenticationKey;
use log::{debug, error, info};
use move_binary_format::{access::ModuleAccess, file_format::AbilitySet, CompiledModule};
use move_compiler::compiled_unit::CompiledUnit;
use move_core_types::account_address::AccountAddress;
use move_package::{
    compilation::compiled_package::{CompiledPackage, CompiledUnitWithSource},
    source_package::manifest_parser::parse_move_manifest_from_file,
};
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
pub fn provision_simulator(simulator: &mut Simulator, project: &Project) -> Result<()> {
    let Project {
        pkgs,
        named_accounts,
        language,
    } = project;

    // pre-compile packages to get compiled metadata
    info!("pre-compiling packages");
    let built_pkgs: Vec<_> = pkgs
        .iter()
        .map(|pkg| package::build(pkg.as_manifest(), named_accounts, *language, false))
        .collect::<Result<_>>()?;

    // populate accounts for project profiles
    info!("populating project accounts");
    let mut num_accounts = 0;
    for (name, account) in named_accounts {
        match account {
            Account::Ref(addr) => {
                simulator.add_address(name.clone(), *addr)?;
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
    for (pkg_decl, pkg_built) in pkgs.iter().zip(built_pkgs) {
        let manifest = pkg_decl.as_manifest();
        let CompiledPackage {
            compiled_package_info,
            root_compiled_units,
            ..
        } = pkg_built.package;

        // derive sender account and also collect modules and scripts
        let mut accounts = BTreeSet::new();
        for CompiledUnitWithSource { unit, source_path } in root_compiled_units {
            match unit {
                CompiledUnit::Module(module) => {
                    accounts.insert(module.address);
                    simulator.add_module(manifest.path.clone(), module.module)?;
                },
                CompiledUnit::Script(script) => {
                    // collect scripts after name check
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
            *language,
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

/// The entry points targetted by this step
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Target {
    Entry { entry: String },
    Public { func: String },
    Script { script: String },
}

/// One step of execution in a runbook
#[derive(Serialize, Deserialize)]
struct Step {
    /// Target to execute
    #[serde(flatten)]
    target: Target,
    /// Signer of the transaction
    signer: String,
    /// Arguments (parameters) for the transaction
    params: Vec<Value>,
    /// Type arguments (a.k.a., type instantiation for generics)
    #[serde(default)]
    typing: Vec<String>,
    /// Expected console output
    #[serde(default)]
    expect: Option<Vec<Value>>,
    /// Events generated
    #[serde(default)]
    events: Option<Vec<String>>,
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

/// A (simplified) copy of aptos::common::types::TransactionSummary as we cannot refer to it
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
enum RunbookEntry {
    Step(Step),
    Info {
        #[serde(rename = "_")]
        info: String,
    },
    Case {
        #[serde(rename = "//")]
        desc: String,
    },
}

/// The runbook (unvalidated)
#[derive(Serialize, Deserialize)]
struct Runbook(Vec<RunbookEntry>);

/// Resolve an argument based on its declared type
fn resolve_argument(
    simulator: &Simulator,
    value: Value,
    ty: &TxnArgType,
    pending_accounts: &mut BTreeMap<String, Ed25519PrivateKey>,
) -> Result<TxnArg> {
    let parsed = match (value, ty) {
        (Value::Bool(v), TxnArgType::Bool) => TxnArg::Bool(v),
        (Value::Number(v), TxnArgType::U8) => TxnArg::U8(v.as_str().parse()?),
        (Value::Number(v), TxnArgType::U16) => TxnArg::U16(v.as_str().parse()?),
        (Value::Number(v), TxnArgType::U32) => TxnArg::U32(v.as_str().parse()?),
        (Value::Number(v), TxnArgType::U64) => TxnArg::U64(v.as_str().parse()?),
        (Value::Number(v), TxnArgType::U128) => TxnArg::U128(v.as_str().parse()?),
        (Value::Number(v), TxnArgType::U256) => TxnArg::U256(v.as_str().parse()?),
        (Value::String(v), TxnArgType::String) => TxnArg::String(v),
        (Value::String(v), TxnArgType::Address) => {
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
            TxnArg::Address(address)
        },
        (Value::String(v), TxnArgType::Signer) => {
            let address = match v.strip_prefix('@') {
                None => bail!("invalid signer {}", v),
                Some(name) => {
                    let addr = match simulator.get_address(name) {
                        None => {
                            let key = pending_accounts
                                .entry(name.to_string())
                                .or_insert_with(|| Ed25519PrivateKey::generate(&mut OsRng));
                            AuthenticationKey::ed25519(&key.public_key()).account_address()
                        },
                        Some(addr) => {
                            match simulator
                                .lookup_namespace_by_address(&addr)
                                .expect("address not found")
                            {
                                AddressNamespace::Owned(..) => addr,
                                AddressNamespace::Ref(..) => bail!(
                                    "passing a signer argument {} without having its key",
                                    name
                                ),
                            }
                        },
                    };
                    debug!("Arg: @{} => {}", name, addr.to_standard_string());
                    addr
                },
            };
            TxnArg::Signer(address)
        },
        (Value::Array(items), TxnArgType::Vector(sub)) => {
            let mut resolved = vec![];
            for item in items {
                resolved.push(resolve_argument(
                    simulator,
                    item,
                    sub.as_ref(),
                    pending_accounts,
                )?);
            }
            TxnArg::Vector(sub.as_ref().clone(), resolved)
        },
        (p, _) => bail!("invalid argument {}", p),
    };
    Ok(parsed)
}

fn create_bridge_script(
    dep_path: &Path,
    module: &CompiledModule,
    function: &str,
    generics: &[AbilitySet],
    params: &[TxnArgTypeWithRef],
    return_ref: Option<bool>,
    path_stage: &Path,
) -> Result<()> {
    // building blocks for the function
    let mut generic_decl = vec![];
    let mut generic_use = vec![];
    for (i, t) in generics.iter().enumerate() {
        generic_decl.push(format!("T{}: {}", i, t));
        generic_use.push(format!("T{}", i));
    }
    let generic_decl_repr = if generic_decl.is_empty() {
        String::new()
    } else {
        format!("<{}>", generic_decl.join(", "))
    };
    let generic_use_repr = if generic_use.is_empty() {
        String::new()
    } else {
        format!("<{}>", generic_use.join(", "))
    };

    let mut param_decl = vec![];
    let mut param_use = vec![];
    for (i, p) in params.iter().enumerate() {
        param_decl.push(format!("p{}: {}", i, p.reduce().type_name()));
        let repr = match p {
            TxnArgTypeWithRef::Base(_) => format!("p{}", i),
            TxnArgTypeWithRef::RefImm(_) => format!("&p{}", i),
            TxnArgTypeWithRef::RefMut(_) => format!("&mut p{}", i),
        };
        param_use.push(repr);
    }

    let (capture_result, print_result) = match return_ref {
        None => ("", ""),
        Some(false) => ("let result = ", "aptos_std::debug::print(&result);"),
        Some(true) => ("let result = ", "aptos_std::debug::print(result);"),
    };

    // piece them together
    let content = format!(
        r#"script {{
    fun wrap_{}{}({}) {{
        {}{}::{}::{}{}({});{}
    }}
}}"#,
        function,
        generic_decl_repr,
        param_decl.join(", "),
        capture_result,
        module.address().to_standard_string(),
        module.name(),
        function,
        generic_use_repr,
        param_use.join(", "),
        print_result,
    );

    // load the dependency name
    let dep_info = parse_move_manifest_from_file(dep_path)?;
    let manifest = format!(
        r#"[package]
name = "TmpScript"
version = "1.0.0"
upgrade_policy = "compatible"
authors = []
[dependencies]
{} = {{ local = "{}" }}
"#,
        dep_info.package.name,
        dep_path.to_str().ok_or_else(|| anyhow!("non-ascii path"))?
    );

    // save the script to file and prepare the package
    fs::create_dir_all(path_stage)?;
    fs::write(path_stage.join("Move.toml"), manifest)?;

    let path_sources = path_stage.join("sources");
    fs::create_dir(&path_sources)?;
    fs::write(path_sources.join("script.move"), content)?;

    Ok(())
}

/// Entrypoint for executing a runbook
pub fn execute_runbook(simulator: &mut Simulator, runbook_path: &Path) -> Result<()> {
    let mut pending_accounts = BTreeMap::new();

    info!("executing runbook at {}", runbook_path.to_string_lossy());
    let book: Runbook = serde_json::from_str(&fs::read_to_string(runbook_path)?)?;

    let mut counter_case = 0;
    let mut counter_step = 0;
    for item in book.0 {
        let step = match item {
            RunbookEntry::Info { info } => {
                info!("/* {} */", info);
                continue;
            },
            RunbookEntry::Case { desc } => {
                counter_case += 1;
                counter_step = 0;
                info!("==== case {}: {} ====", counter_case, desc);
                continue;
            },
            RunbookEntry::Step(s) => s,
        };
        counter_step += 1;

        let Step {
            target,
            signer,
            params,
            typing,
            expect,
            events: expecting_events,
            aborts,
        } = step;
        info!(
            "step {}: {} [{}] {}",
            counter_step,
            match &target {
                Target::Entry { entry } => entry,
                Target::Public { func } => func,
                Target::Script { script } => script,
            },
            signer,
            params
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        );

        // a temp directory to host this execution
        let tmp = TempDir::new()?;

        // probe the signature and parse the target
        let (generics, arg_types, runnable) = match target {
            Target::Entry { entry } => {
                let idents = entry.split("::").collect::<Vec<_>>();
                let (_, module, generics, arg_types) = match idents.len() {
                    1 => simulator.lookup_entry_function(None, idents[0])?,
                    2 => simulator.lookup_entry_function(Some((None, idents[0])), idents[1])?,
                    3 => match simulator.get_address(idents[0]) {
                        None => bail!("invalid named address: {}", idents[0]),
                        Some(addr) => simulator
                            .lookup_entry_function(Some((Some(addr), idents[1])), idents[2])?,
                    },
                    _ => bail!("malformed entry function identifier: {}", entry),
                };
                (generics, arg_types, Runnable::Entry {
                    address: *module.address(),
                    module: module.name().to_string(),
                    function: idents.last().expect("function name").to_string(),
                })
            },
            Target::Public { func } => {
                let idents = func.split("::").collect::<Vec<_>>();
                let (pkg_dir, module, generics, arg_types, return_ref) = match idents.len() {
                    1 => simulator.lookup_public_function(None, idents[0])?,
                    2 => simulator.lookup_public_function(Some((None, idents[0])), idents[1])?,
                    3 => match simulator.get_address(idents[0]) {
                        None => bail!("invalid named address: {}", idents[0]),
                        Some(addr) => simulator
                            .lookup_public_function(Some((Some(addr), idents[1])), idents[2])?,
                    },
                    _ => bail!("malformed public function identifier: {}", func),
                };

                // need to formulate a new Move script
                let code_path = tmp.path().join("autogen_script");
                create_bridge_script(
                    pkg_dir,
                    module,
                    idents.last().expect("function name"),
                    &generics,
                    &arg_types,
                    return_ref,
                    &code_path,
                )?;

                let exec_path = tmp.path().join("executable.mv");
                simulator.compile_script(&code_path, &exec_path)?;
                (
                    generics,
                    arg_types.iter().map(TxnArgTypeWithRef::reduce).collect(),
                    Runnable::Script { path: exec_path },
                )
            },
            Target::Script { script: name } => {
                let (script, generics, arg_types) = simulator.lookup_script(&name)?;

                // first deserialize the script
                let mut bytes = vec![];
                script.serialize(&mut bytes)?;
                let exec_path = tmp.path().join("executable.mv");
                fs::write(&exec_path, &bytes)?;

                // then return the runnable
                (generics, arg_types, Runnable::Script { path: exec_path })
            },
        };

        // check generics matches
        if generics.len() != typing.len() {
            bail!("wrong number of type arguments");
        }

        // parse and validate arguments
        let mut entry_sig_iter = arg_types.iter();
        if arg_types.len() == params.len() + 1 {
            match entry_sig_iter.next().unwrap() {
                TxnArgType::Signer => (),
                _ => {
                    bail!(
                        "wrong number of arguments (NOTE: the first parameter is not a signer type)"
                    )
                },
            }
        } else if arg_types.len() != params.len() {
            bail!("wrong number of parameters");
        }

        // parse arguments
        let mut parsed_args = vec![];
        for (param, token) in params.into_iter().zip(entry_sig_iter) {
            let arg = resolve_argument(simulator, param, token, &mut pending_accounts)?;
            parsed_args.push(arg);
        }

        // validate and transform expected events, if any
        let check_events = match expecting_events {
            None => None,
            Some(event_tags) => {
                let mut parsed_tags = vec![];
                for tag in event_tags {
                    let idents = tag.split("::").collect::<Vec<_>>();
                    let (_, module) = match idents.len() {
                        1 => simulator.lookup_struct(None, idents[0])?,
                        2 => simulator.lookup_struct(Some((None, idents[0])), idents[1])?,
                        3 => match simulator.get_address(idents[0]) {
                            None => bail!("invalid named address: {}", idents[0]),
                            Some(addr) => {
                                simulator.lookup_struct(Some((Some(addr), idents[1])), idents[2])?
                            },
                        },
                        _ => bail!("malformed event identifier: {}", tag),
                    };
                    parsed_tags.push(format!(
                        "{}::{}::{}",
                        module.address().to_canonical_string(),
                        module.name(),
                        idents.last().expect("event struct name")
                    ));
                }
                Some(parsed_tags)
            },
        };

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

        // execute the target (first in simulate mode)
        let (success, stdout) = simulator.run(signer, &runnable, &typing, &parsed_args, true)?;
        if !success {
            bail!(
                "script simulation failed at case {} step {}",
                counter_case,
                counter_step,
            );
        }

        // analyze the output
        let mut debugs = vec![];
        let mut events = vec![];
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
            } else if let Some(msg) = line.strip_prefix("[event] ") {
                if msg
                    == format!(
                        "{}::transaction_fee::FeeStatement",
                        AccountAddress::ONE.to_canonical_string()
                    )
                {
                    // HACK: we don't care about this FeeStatement event
                    continue;
                }
                // capture event items
                events.push(msg);
            }
        }

        // extract the result
        let response: StepResponse = serde_json::from_str(&result.join("\n"))?;
        match (aborts, response.result.success) {
            (true, true) => bail!("expect failure while transaction executed"),
            (false, false) => bail!("expect success while transaction failed"),
            _ => (),
        }

        // cross-check the debug messages (if explicitly requested)
        if let Some(debugs_expect) = expect {
            if debugs.len() != debugs_expect.len() {
                error!("debug messages received:");
                for item in debugs {
                    error!("  {}", item);
                }
                bail!("output does not match with expectation");
            }
            for (index, (message, expected)) in debugs.into_iter().zip(debugs_expect).enumerate() {
                let remapped = match &expected {
                    Value::Bool(v) => v.to_string(),
                    Value::Number(v) => v.to_string(),
                    Value::String(v) => match v.strip_prefix('@') {
                        None => format!("\"{}\"", v),
                        Some(name) => {
                            if name.starts_with("0x") {
                                name.to_string()
                            } else {
                                let addr = simulator
                                    .get_address(name)
                                    .ok_or_else(|| anyhow!("no such named address: {}", name))?;
                                format!("@{}", addr.to_standard_string())
                            }
                        },
                    },
                    _ => bail!("not supported yet"),
                };
                if message != remapped {
                    bail!(
                        "output mismatch at index {}: expect {}, actual {}",
                        index,
                        remapped,
                        message
                    );
                }
            }
        }

        // cross-check the events (if explicitly requested)
        if let Some(events_expect) = check_events {
            if events.len() != events_expect.len() {
                error!("events emitted:");
                for item in events {
                    error!("  {}", item);
                }
                bail!("event sequence does not match with expectation");
            }
            for (index, (actual, expected)) in events.into_iter().zip(events_expect).enumerate() {
                if actual != expected {
                    bail!(
                        "event mismatch at index {}: expect {}, actual {}",
                        index,
                        expected,
                        actual
                    );
                }
            }
        }

        // execute the script (now in commit mode)
        let (success, _) = simulator.run(signer, &runnable, &typing, &parsed_args, false)?;
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
