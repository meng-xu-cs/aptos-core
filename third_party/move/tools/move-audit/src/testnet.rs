use crate::{common::Account, config::APTOS_BIN, deps::PkgManifest, package, Project};
use anyhow::{anyhow, bail, Result};
use command_group::{CommandGroup, GroupChild, Signal, UnixChildExt};
use log::{debug, error, info};
use std::{
    collections::BTreeMap,
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

/// Populate workspace accounts for project profiles
pub fn init_project_accounts(wks: &Path, named_accounts: &BTreeMap<String, Account>) -> Result<()> {
    for (name, account) in named_accounts {
        match account {
            Account::Ref(_) => (),
            Account::Owned(key) => {
                let key_string = format!("0x{}", hex::encode(key.to_bytes()));

                // register the profile
                let status = Command::new(APTOS_BIN.as_path())
                    .args([
                        "init",
                        "--network",
                        "local",
                        "--profile",
                        name.as_str(),
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
                        name.as_str(),
                        "--account",
                        name.as_str(),
                        "--amount",
                        &ACCOUNT_INITIAL_FUND.to_string(),
                    ])
                    .current_dir(wks)
                    .spawn()?
                    .wait()?;
                if !status.success() {
                    bail!("failed to fund account {}", name);
                }
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
        let pkg = package::build(manifest, false)?;
    }
    Ok(())
}
