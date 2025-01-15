use crate::common::PkgDefinition;
use anyhow::{bail, Result};
use aptos_language_e2e_tests::{account::Account, executor::FakeExecutor};
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
#[derive(Debug, Copy, Clone)]
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

/// Address dictionary
pub struct AddressDict {
    details: BTreeMap<AccountAddress, AddressDetails>,
    named_addresses: BTreeMap<NamedAddress, AccountAddress>,
    user_addresses: BTreeMap<UserId, AccountAddress>,
}

impl AddressDict {
    /// Create an empty dictionary
    pub fn new() -> Self {
        Self {
            details: BTreeMap::new(),
            named_addresses: BTreeMap::new(),
            user_addresses: BTreeMap::new(),
        }
    }

    /// Report a `(name, addr)` pair to the dictionary
    pub fn sync_named_address<F1, F2>(
        &mut self,
        name: NamedAddress,
        addr: AccountAddress,
        fn_and_check: F1,
        fn_or_insert: F2,
    ) -> Result<()>
    where
        F1: FnOnce(NamedAddressKind) -> Result<()>,
        F2: FnOnce(AccountAddress) -> (NamedAddressKind, Account),
    {
        match (self.named_addresses.get(&name), self.details.get_mut(&addr)) {
            (None, None) => {
                self.named_addresses.insert(name, addr);
                let names = std::iter::once(name).collect();
                let (kind, account) = fn_or_insert(addr);
                self.details.insert(addr, AddressDetails::Named {
                    kind,
                    names,
                    account,
                });
                log::debug!("named address {name}: {addr} registered as {kind}");
            },
            (
                None,
                Some(AddressDetails::Named {
                    kind,
                    names,
                    account: _,
                }),
            ) => {
                fn_and_check(*kind)?;
                self.named_addresses.insert(name, addr);
                let inserted = names.insert(name);
                assert!(inserted);
                log::debug!("named address {name}: {addr} associated as {kind}");
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
                        fn_and_check(*kind)?;
                        assert!(names.contains(&name));
                    },
                    _ => bail!("expecting {addr} to be a named address, found '{details}'"),
                }
            },
        };
        Ok(())
    }
}

/// Hold all information about the fuzz targets
pub struct FuzzModel {
    /// stateful executor
    executor: FakeExecutor,

    /// address dictionary
    address_dict: AddressDict,
}

impl FuzzModel {
    /// Create the fuzz model from compiled packages
    pub fn new(pkgs: &[PkgDefinition]) -> Result<Self> {
        // create a fake executor with genesis provisioned
        let mut executor = FakeExecutor::from_head_genesis().set_not_parallel();
        log::debug!("local executor created with head genesis");

        // collect addresses into a dictionary
        let mut address_dict = AddressDict::new();

        // process packages in the order of their dependency chain
        for pkg in pkgs {
            match pkg {
                PkgDefinition::Framework(compiled_package) => {
                    // every named address in a framework package will be marked
                    // and should stay as a reserved address
                    for (&name, &addr) in &compiled_package
                        .compiled_package_info
                        .address_alias_instantiation
                    {
                        address_dict.sync_named_address(
                            name,
                            addr,
                            |kind| {
                                if !matches!(kind, NamedAddressKind::Reserved) {
                                    bail!("expect {addr} to be a 'Reserved' address, found {kind}");
                                }
                                Ok(())
                            },
                            |a| (NamedAddressKind::Reserved, executor.new_account_at(a)),
                        )?;
                    }
                },
                PkgDefinition::Dependency(compiled_package) => {
                    // if we have already added the named address in dictionary,
                    // do nothing, otherwise, create an account and register
                    // the named address as `Dependency` kind
                    for (&name, &addr) in &compiled_package
                        .compiled_package_info
                        .address_alias_instantiation
                    {
                        address_dict.sync_named_address(
                            name,
                            addr,
                            |_| Ok(()),
                            |a| (NamedAddressKind::Dependency, executor.new_account_at(a)),
                        )?;
                    }
                },
                PkgDefinition::Primary(compiled_package) => {
                    // if we have already added the named address in dictionary,
                    // do nothing, otherwise, create an account and register
                    // the named address as `Primary` kind
                    for (&name, &addr) in &compiled_package
                        .compiled_package_info
                        .address_alias_instantiation
                    {
                        address_dict.sync_named_address(
                            name,
                            addr,
                            |_| Ok(()),
                            |a| (NamedAddressKind::Primary, executor.new_account_at(a)),
                        )?;
                    }
                },
            }
        }

        // done
        Ok(Self {
            executor,
            address_dict,
        })
    }
}
