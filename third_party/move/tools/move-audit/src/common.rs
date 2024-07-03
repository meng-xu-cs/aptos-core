use crate::deps::PkgManifest;
use anyhow::{bail, Result};
use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey};
use aptos_types::transaction::authenticator::AuthenticationKey;
use move_core_types::account_address::AccountAddress;
use std::{collections::BTreeMap, fs, path::PathBuf};

const WORKSPACE_DIRECTORY: &str = ".aptos";

/// Account (either referenced or owned)
pub enum Account {
    Ref(AccountAddress),
    Owned(Ed25519PrivateKey),
}

impl Account {
    pub fn address(&self) -> AccountAddress {
        match self {
            Self::Ref(addr) => *addr,
            Self::Owned(key) => AuthenticationKey::ed25519(&key.public_key()).account_address(),
        }
    }
}

/// A Move audit project composed by a list of packages to audit
pub struct Project {
    pub root: PathBuf,
    pub pkgs: Vec<(PkgManifest, bool)>,
    pub named_accounts: BTreeMap<String, Account>,
}
