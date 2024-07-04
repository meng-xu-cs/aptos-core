use crate::{common::Account, config::APTOS_BIN, deps::PkgManifest, package};
use anyhow::{anyhow, bail, Result};
use aptos_crypto::{ed25519::Ed25519PrivateKey, Uniform};
use command_group::{CommandGroup, GroupChild, Signal, UnixChildExt};
use log::{debug, error, info};
use move_binary_format::file_format::CompiledScript;
use move_compiler::compiled_unit::{CompiledUnit, NamedCompiledScript};
use move_package::compilation::compiled_package::{CompiledPackage, CompiledUnitWithSource};
use rand::rngs::OsRng;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
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

pub enum ScriptSigner {
    Single(String, Option<Ed25519PrivateKey>),
    Multi(Vec<(String, Option<Ed25519PrivateKey>)>),
}

pub struct ExecutableScript {
    pub script: CompiledScript,
    pub signer: ScriptSigner,
}

fn extract_script(
    source: &Path,
    script: NamedCompiledScript,
    named_accounts: &BTreeMap<String, Account>,
) -> Result<ExecutableScript> {
    let mut config = vec![];
    let mut new_names = BTreeSet::new();

    let content = fs::read_to_string(source)?;
    for line in content.lines() {
        let name = match line.strip_prefix("//:s ") {
            None => {
                // requires consecutive config lines
                break;
            },
            Some(rest) => rest,
        };

        let key = if named_accounts.contains_key(name) {
            None
        } else {
            if !new_names.insert(name.to_string()) {
                bail!("the same signer is declared more than once: {}", name);
            }
            Some(Ed25519PrivateKey::generate(&mut OsRng))
        };
        config.push((name.to_string(), key));
    }

    // ensure that we have at least one signer
    if config.is_empty() {
        bail!("no signer is declared");
    }

    let signer = if config.len() == 1 {
        let (name, new_key) = config.pop().unwrap();
        ScriptSigner::Single(name, new_key)
    } else {
        ScriptSigner::Multi(config)
    };

    Ok(ExecutableScript {
        script: script.script,
        signer,
    })
}

/// Publish packages in the project and return executable scripts
pub fn publish_project_packages(
    wks: &Path,
    pkgs: &[(PkgManifest, bool)],
    named_accounts: &BTreeMap<String, Account>,
) -> Result<BTreeMap<PathBuf, ExecutableScript>> {
    // collect executable scripts
    let mut executables = BTreeMap::new();

    for (manifest, is_primary) in pkgs {
        // only publish primary packages
        if !*is_primary {
            continue;
        }

        // compile the package first
        let CompiledPackage {
            compiled_package_info,
            root_compiled_units,
            ..
        } = package::build(manifest, named_accounts, false)?;

        // derive sender account and also collect executable scripts
        let mut accounts = BTreeSet::new();
        for CompiledUnitWithSource { unit, source_path } in root_compiled_units {
            match unit {
                CompiledUnit::Module(module) => {
                    accounts.insert(module.address);
                },
                CompiledUnit::Script(script) => {
                    let path_script = source_path.canonicalize()?;
                    let exec_script = extract_script(&path_script, script, named_accounts)?;
                    let existing = executables.insert(path_script, exec_script);
                    if existing.is_some() {
                        bail!("symbolic links in the script paths is not supported");
                    }
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
        let mut filtered = compiled_package_info
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
        let named_address_pairs: Vec<_> = compiled_package_info
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

    // return the collected executables
    Ok(executables)
}

/// Execute a script
pub fn execute_script(wks: &Path, path: &Path, exec: ExecutableScript) -> Result<()> {
    info!("executing script {}", path.to_string_lossy());
    let ExecutableScript { signer, script } = exec;

    // deserialize the script
    let mut bytes = vec![];
    script.serialize(&mut bytes)?;

    let exec_path = wks.join("executable.mv");
    fs::write(&exec_path, bytes)?;

    // prepare the signer
    match signer {
        ScriptSigner::Single(account, new_key) => {
            if let Some(key) = new_key {
                populate_account(wks, &account, &key)?;
            }
            // execute the script
            let status = Command::new(APTOS_BIN.as_path())
                .args(["move", "run-script"])
                .arg("--compiled-script-path")
                .arg(&exec_path)
                .args(["--profile", &account, "--sender-account", &account])
                .arg("--local")
                .current_dir(wks)
                .spawn()?
                .wait()?;
            if !status.success() {
                bail!("failed to execute script {}", path.to_string_lossy());
            }
        },

        ScriptSigner::Multi(..) => unimplemented!("multi-sig not supported yet"),
    }

    // done
    Ok(())
}
