use anyhow::{bail, Result};
use aptos_language_e2e_tests::account::Account;
use move_core_types::account_address::AccountAddress;
use move_package::source_package::parsed_manifest::NamedAddress;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

/// Represents a unique user account
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct UserId(usize);

/// Types of named address
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum NamedAddressKind {
    Reserved,
    Dependency,
    Primary,
}

impl Display for NamedAddressKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reserved => write!(f, "Reserved"),
            Self::Dependency => write!(f, "Dependency"),
            Self::Primary => write!(f, "Primary"),
        }
    }
}

/// Details about the nature of an address
pub enum AddressDetails {
    /// a named address declared in Move package manifest
    Named {
        kind: NamedAddressKind,
        names: BTreeSet<NamedAddress>,
        account: Account,
    },

    /// an address that represents a normal user who interacts with the system
    User { id: UserId, account: Account },
}

impl Display for AddressDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named {
                kind,
                names,
                account: _,
            } => write!(
                f,
                "{kind}({})",
                names
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::User { id, account: _ } => write!(f, "User({})", id.0),
        }
    }
}

/// Address registry
pub struct AddressRegistry {
    /// mapping from address to address/account details
    details: BTreeMap<AccountAddress, AddressDetails>,

    /// mapping from named address (i.e., string symbols) to address
    named_addresses: BTreeMap<NamedAddress, AccountAddress>,
    /// mapping from user id to address
    user_addresses: BTreeMap<UserId, AccountAddress>,
}

impl AddressRegistry {
    /// Create an empty registry
    pub fn new() -> Self {
        Self {
            details: BTreeMap::new(),
            named_addresses: BTreeMap::new(),
            user_addresses: BTreeMap::new(),
        }
    }

    /// Report a `(name, addr)` pair to the registry
    /// - If the pair does not exist, create an account and insert it
    /// - If `addr` exists but `name` is new, link them after validation
    /// - If `name` exists but `addr` is new, this is definitely an error
    /// - If both exist, check `addr` if needed
    ///
    /// Return the account if new account is created, `None` otherwise.
    pub fn sync_named_address(
        &mut self,
        name: NamedAddress,
        addr: AccountAddress,
        kind_to_check_on_exists: Option<NamedAddressKind>,
        kind_to_insert_on_empty: NamedAddressKind,
    ) -> Result<Option<Account>> {
        let account_created = match (self.named_addresses.get(&name), self.details.get_mut(&addr)) {
            (None, None) => {
                let names = std::iter::once(name).collect();
                // NOTE: here it means all accounts created by our executor
                // share the same key pair, but that seems okay.
                let account = Account::new_genesis_account(addr);
                self.details.insert(addr, AddressDetails::Named {
                    kind: kind_to_insert_on_empty,
                    names,
                    account: account.clone(),
                });
                self.named_addresses.insert(name, addr);
                log::debug!("named address {name}: {addr} registered as {kind_to_insert_on_empty}");

                // mark that new account is created
                Some(account)
            },
            (
                None,
                Some(AddressDetails::Named {
                    kind,
                    names,
                    account: _,
                }),
            ) => {
                match kind_to_check_on_exists {
                    Some(expected) if expected != *kind => {
                        bail!("expect {name}:{addr} to be {expected}, found {kind}");
                    },
                    _ => (),
                }

                let inserted = names.insert(name);
                assert!(inserted);
                self.named_addresses.insert(name, addr);
                log::debug!("named address {name}: {addr} associated as {kind}");

                // no new account created
                None
            },
            (None, Some(details)) => {
                bail!("expecting {addr} to be a named address, found '{details}'");
            },
            (Some(previous), None) => bail!(
                "conflicting assignment for named address {name}: {addr}, \
                 {name} is already bound to {previous} and {addr} does not exist"
            ),
            (Some(previous), Some(details)) => {
                if previous != &addr {
                    bail!(
                        "conflicting assignment for named address {name}: {addr}, \
                         {name} is already bound to {previous} and {addr} is {details}"
                    );
                }
                match details {
                    AddressDetails::Named {
                        kind,
                        names,
                        account: _,
                    } => {
                        match kind_to_check_on_exists {
                            Some(expected) if expected != *kind => {
                                bail!("expect {name}:{addr} to be {expected}, found {kind}");
                            },
                            _ => (),
                        }
                        assert!(names.contains(&name));
                    },
                    _ => bail!("expecting {addr} to be a named address, found '{details}'"),
                }

                // no new account created
                None
            },
        };
        Ok(account_created)
    }

    /// Lookup the account from an address
    pub fn lookup_account(&self, addr: AccountAddress) -> Option<&Account> {
        match self.details.get(&addr)? {
            AddressDetails::Named { account, .. } | AddressDetails::User { account, .. } => {
                Some(account)
            },
        }
    }
}
