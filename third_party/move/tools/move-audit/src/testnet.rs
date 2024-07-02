use crate::{common::Account, config::APTOS_BIN, Project, Workspace};
use anyhow::{anyhow, bail, Result};
use aptos_crypto::ed25519::{Ed25519PrivateKey, Ed25519PublicKey};
use command_group::{CommandGroup, GroupChild, Signal, UnixChildExt};
use log::{debug, error, info};
use move_core_types::account_address::AccountAddress;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader},
    path::Path,
    process::{Command, Stdio},
    sync::{Arc, Condvar, Mutex},
    thread,
    thread::JoinHandle,
};

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
pub fn launch_local_testnet(path: &Path, wks: &Workspace, restart: bool) -> Result<Subcommand> {
    // spawn the process
    debug!("launching local testnet");

    let mut cmd = Command::new(APTOS_BIN.as_path());
    cmd.args(["node", "run-local-testnet", "--with-faucet"])
        .arg("--test-dir")
        .arg(&wks.testnet);
    if restart {
        cmd.arg("--force-restart");
    }
    cmd.current_dir(path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.group_spawn()?;

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

/// Populate workspace accounts
pub fn init_local_testnet_profiles(project: &Project) -> Result<()> {
    for (name, account) in &project.named_accounts {
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
                    .current_dir(&project.root)
                    .spawn()?
                    .wait()?;
                if !status.success() {
                    bail!("failed to initialize profile {}", name);
                }
            },
        }
    }
    Ok(())
}

/// An individual profile
#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    pub private_key: Ed25519PrivateKey,
    pub public_key: Ed25519PublicKey,
    pub account: AccountAddress,
    pub rest_url: String,
    pub faucet_url: String,
}

/// Config saved to `.aptos/config.yaml`
#[derive(Debug, Serialize, Deserialize)]
pub struct ProfileConfig {
    pub profiles: BTreeMap<String, Profile>,
}

impl ProfileConfig {
    pub fn load(wks: &Workspace) -> Result<Self> {
        let content = fs::read_to_string(&wks.config)?;
        let config = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}
