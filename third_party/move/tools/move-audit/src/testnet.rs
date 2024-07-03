use crate::{common::Account, config::APTOS_BIN, deps::PkgManifest, package};
use anyhow::{anyhow, bail, Result};
use aptos_crypto::{ed25519::Ed25519PrivateKey, Uniform};
use command_group::{CommandGroup, GroupChild, Signal, UnixChildExt};
use log::{debug, error, info};
use move_compiler::compiled_unit::CompiledUnit;
use rand::rngs::OsRng;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader},
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Condvar, Mutex},
    thread,
    thread::JoinHandle,
};

const ACCOUNT_INITIAL_FUND: u64 = 100000000;

/// A subcommand group capturing the child execution
pub struct Subcommand {
    child: GroupChild,
    thread_stdout: JoinHandle<Result<()>>,
    thread_stderr: JoinHandle<Result<()>>,
}

impl Subcommand {
    pub fn interrupt(self) -> Result<()> {
        let Self {
            mut child,
            thread_stdout,
            thread_stderr,
        } = self;

        let mut errors = vec![];

        // consolidate errors
        match child.signal(Signal::SIGINT) {
            Ok(()) => (),
            Err(e1) => {
                error!("unable to SIGINT child with PID {}: {}", child.id(), e1);
                errors.push(e1.to_string());

                match child.kill() {
                    Ok(()) => (),
                    Err(e2) => {
                        error!("unable to SIGKILL child with PID {}: {}", child.id(), e2);
                        errors.push(e2.to_string());
                    },
                }
            },
        };
        match thread_stdout.join() {
            Ok(Ok(())) => (),
            Ok(Err(e)) => {
                errors.push(e.to_string());
            },
            Err(e) => {
                panic!("stdout thread panics with {:?}", e);
            },
        }
        match thread_stderr.join() {
            Ok(Ok(())) => (),
            Ok(Err(e)) => {
                errors.push(e.to_string());
            },
            Err(e) => {
                panic!("stderr thread panics with {:?}", e);
            },
        }

        // finish with the result
        if !errors.is_empty() {
            bail!(anyhow!(errors.join("\n")));
        }
        Ok(())
    }
}

/// Launch the local testnet
pub fn init_local_testnet(wks: &Path) -> Result<Subcommand> {
    // spawn the process
    debug!("launching local testnet");

    let mut child = Command::new(APTOS_BIN.as_path())
        .args([
            "node",
            "run-local-testnet",
            "--with-faucet",
            "--force-restart",
        ])
        .current_dir(wks)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .group_spawn()?;

    // prepare for reader threads
    let stderr = child.inner().stderr.take().expect("piped stderr");
    let stdout = child.inner().stdout.take().expect("piped stdout");

    let pair_parent = Arc::new((Mutex::new(false), Condvar::new()));
    let pair_child = Arc::clone(&pair_parent);

    let thread_stderr = thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            match line {
                Ok(l) => {
                    if l == "Setup is complete, you can now use the localnet!" {
                        let (lock, cvar) = &*pair_child;
                        let mut ready = lock.lock().unwrap();
                        *ready = true;
                        cvar.notify_one();
                    }
                    debug!("{}", l);
                },
                Err(e) => bail!(e),
            }
        }
        Ok(())
    });

    let thread_stdout = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(l) => info!("{}", l),
                Err(e) => bail!(e),
            }
        }
        Ok(())
    });

    // wait for readiness
    let (lock, cvar) = &*pair_parent;
    let mut ready = lock.lock().unwrap();
    while !*ready {
        ready = cvar.wait(ready).unwrap();
    }
    debug!("local testnet is ready");

    // return the pack
    Ok(Subcommand {
        child,
        thread_stdout,
        thread_stderr,
    })
}

fn populate_account(wks: &Path, name: &str, key: &Ed25519PrivateKey) -> Result<()> {
    let key_string = format!("0x{}", hex::encode(key.to_bytes()));

    // register the profile
    let status = Command::new(APTOS_BIN.as_path())
        .args([
            "init",
            "--network",
            "local",
            "--profile",
            name,
            "--private-key",
            key_string.as_str(),
            "--skip-faucet",
            "--assume-yes",
        ])
        .current_dir(wks)
        .spawn()?
        .wait()?;
    if !status.success() {
        bail!("failed to initialize account {}", name);
    }

    // fund the account
    let status = Command::new(APTOS_BIN.as_path())
        .args([
            "account",
            "fund-with-faucet",
            "--profile",
            name,
            "--account",
            name,
            "--amount",
            &ACCOUNT_INITIAL_FUND.to_string(),
        ])
        .current_dir(wks)
        .spawn()?
        .wait()?;
    if !status.success() {
        bail!("failed to fund account {}", name);
    }

    // done
    Ok(())
}

/// Populate workspace accounts for project profiles
pub fn init_project_accounts(wks: &Path, named_accounts: &BTreeMap<String, Account>) -> Result<()> {
    for (name, account) in named_accounts {
        match account {
            Account::Ref(_) => (),
            Account::Owned(key) => {
                populate_account(wks, name, key)?;
            },
        }
    }
    Ok(())
}

/// Publish packages in the project
pub fn publish_project_packages(
    wks: &Path,
    pkgs: &[(PkgManifest, bool)],
    named_accounts: &BTreeMap<String, Account>,
) -> Result<()> {
    for (manifest, is_primary) in pkgs {
        // only publish primary packages
        if !*is_primary {
            continue;
        }

        // compile the package first
        let pkg = package::build(manifest, named_accounts, false)?;

        // derive sender account
        let mut accounts = BTreeSet::new();
        for unit in &pkg.root_compiled_units {
            match &unit.unit {
                CompiledUnit::Module(module) => {
                    accounts.insert(module.address);
                },
                CompiledUnit::Script(_) => {
                    bail!(
                        "unexpected script in package to publish: {}",
                        unit.source_path.to_string_lossy()
                    );
                },
            }
        }

        if accounts.is_empty() {
            // no modules to publish, skip this package
            continue;
        }
        let mut iter = accounts.into_iter();
        let sender = match iter.next() {
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

        // reverse lookup the name
        let mut filtered = pkg
            .compiled_package_info
            .address_alias_instantiation
            .iter()
            .filter_map(|(name, addr)| {
                if addr == &sender {
                    Some(name.as_str())
                } else {
                    None
                }
            });
        let account = match filtered.next() {
            None => {
                bail!("unable to find the owner of address 0x{}", sender);
            },
            Some(name) => {
                if filtered.next().is_some() {
                    bail!("more than one owners identified to publish all modules");
                }
                name
            },
        };

        // build named addresses for cli invocation
        let named_address_pairs: Vec<_> = pkg
            .compiled_package_info
            .address_alias_instantiation
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect();

        // publish the package
        let status = Command::new(APTOS_BIN.as_path())
            .args([
                "move",
                "publish",
                "--included-artifacts",
                "none",
                "--profile",
                account,
                "--sender-account",
                account,
                "--skip-fetch-latest-git-deps",
                "--override-size-check",
            ])
            .arg("--package-dir")
            .arg(&manifest.path)
            .arg("--named-addresses")
            .arg(named_address_pairs.join(","))
            .arg("--assume-yes")
            .current_dir(wks)
            .spawn()?
            .wait()?;
        if !status.success() {
            bail!("failed to publish package {}", manifest.name);
        }
    }
    Ok(())
}

fn extract_script_config(
    path: &Path,
    named_accounts: &BTreeMap<String, Account>,
) -> Result<(BTreeMap<String, Ed25519PrivateKey>, String)> {
    let mut new_keys = BTreeMap::new();
    let mut signer = None;

    let content = fs::read_to_string(path)?;
    for line in content.lines() {
        let config = match line.strip_prefix("//:") {
            None => {
                // requires consecutive config lines
                break;
            },
            Some(rest) => rest,
        };

        let tokens: Vec<_> = config.split(' ').collect();
        if tokens.len() != 2 {
            bail!(
                "invalid config line '{}' in script {}",
                line,
                path.to_string_lossy()
            );
        }

        let val = tokens.last().unwrap().trim();
        match *tokens.first().unwrap() {
            "a" => {
                if named_accounts.contains_key(val) {
                    bail!("cannot re-declare a project account: {}", val);
                }
                if new_keys.contains_key(val) {
                    bail!("the same account is declared more than once: {}", val);
                }
                new_keys.insert(val.to_string(), Ed25519PrivateKey::generate(&mut OsRng));
            },
            "s" => {
                if signer.is_some() {
                    bail!("signer is declared more than once");
                }
                if !named_accounts.contains_key(val) {
                    if new_keys.contains_key(val) {
                        bail!("the same account is declared more than once: {}", val);
                    }
                    new_keys.insert(val.to_string(), Ed25519PrivateKey::generate(&mut OsRng));
                }
                signer = Some(val.to_string());
            },
            _ => bail!(
                "invalid config line '{}' in script {}",
                line,
                path.to_string_lossy()
            ),
        };
    }

    // ensure that we have a signer
    let name = match signer {
        None => bail!("no signer is declared"),
        Some(s) => s,
    };

    Ok((new_keys, name))
}

/// Execute a move script
pub fn execute_script(
    wks: &Path,
    index: usize,
    script: &Path,
    named_accounts: &BTreeMap<String, Account>,
) -> Result<()> {
    // extract configs
    let (new_keys, signer) = extract_script_config(script, named_accounts)?;

    let mut new_accounts = BTreeMap::new();
    for (name, key) in new_keys {
        populate_account(wks, &name, &key)?;
        new_accounts.insert(name, Account::Owned(key));
    }

    // compile the script
    let compiled = wks.join(format!("{}.mv", index));
    let named_address_pairs: Vec<_> = named_accounts
        .iter()
        .chain(new_accounts.iter())
        .map(|(k, v)| format!("{}={}", k, v.address()))
        .collect();

    let status = Command::new(APTOS_BIN.as_path())
        .args(["move", "compile-script"])
        .arg("--skip-fetch-latest-git-deps")
        .args(["--named-addresses", &named_address_pairs.join(",")])
        .arg("--output-file")
        .arg(&compiled)
        .arg(script)
        .current_dir(wks)
        .spawn()?
        .wait()?;
    if !status.success() {
        bail!("failed to compile script {}", script.to_string_lossy());
    }

    Ok(())
}
