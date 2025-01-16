use crate::common::PkgDefinition;
use anyhow::{anyhow, bail, Result};
use aptos_cached_packages::aptos_stdlib;
use aptos_framework::{BuiltPackage, UPGRADE_POLICY_CUSTOM_FIELD};
use aptos_language_e2e_tests::{account::Account, executor::FakeExecutor};
use move_compiler::compiled_unit::CompiledUnit;
use move_core_types::account_address::AccountAddress;
use move_package::{
    compilation::compiled_package::{CompiledPackage, CompiledUnitWithSource},
    package_hooks::{register_package_hooks, PackageHooks},
    source_package::parsed_manifest::{CustomDepInfo, NamedAddress},
};
use move_symbol_pool::Symbol;
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

    /// Lookup the account from an address
    pub fn lookup_account(&self, addr: AccountAddress) -> Option<&Account> {
        match self.details.get(&addr)? {
            AddressDetails::Named { account, .. } | AddressDetails::User { account, .. } => {
                Some(account)
            },
        }
    }
}

/// A utility struct for providing the `PackageHooks` implementation
struct AptosPackageHooks;

impl PackageHooks for AptosPackageHooks {
    fn custom_package_info_fields(&self) -> Vec<String> {
        vec![UPGRADE_POLICY_CUSTOM_FIELD.to_string()]
    }

    fn custom_dependency_key(&self) -> Option<String> {
        Some("aptos".to_string())
    }

    fn resolve_custom_dependency(&self, _dep_name: Symbol, _info: &CustomDepInfo) -> Result<()> {
        bail!("[invariant] custom dependency resolution is not supported")
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
        register_package_hooks(Box::new(AptosPackageHooks {}));
        let mut executor = FakeExecutor::from_head_genesis().set_not_parallel();
        log::debug!("local executor created with head genesis");

        // collect addresses into a dictionary
        let mut address_dict = AddressDict::new();

        // process packages in the order of their dependency chain
        for pkg in pkgs {
            match pkg {
                PkgDefinition::Framework(built_package) => {
                    // every named address in a framework package will be marked
                    // and should stay as a reserved address
                    for (&name, &addr) in &built_package
                        .package
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
                PkgDefinition::Dependency(built_package) => {
                    Self::provision_package(
                        &mut executor,
                        &mut address_dict,
                        NamedAddressKind::Dependency,
                        built_package,
                    )?;
                },
                PkgDefinition::Primary(built_package) => {
                    Self::provision_package(
                        &mut executor,
                        &mut address_dict,
                        NamedAddressKind::Primary,
                        built_package,
                    )?;
                },
            }
        }

        // done
        Ok(Self {
            executor,
            address_dict,
        })
    }

    fn provision_package(
        executor: &mut FakeExecutor,
        address_dict: &mut AddressDict,
        address_kind: NamedAddressKind,
        built_package: &BuiltPackage,
    ) -> Result<()> {
        // collect addresses and create accounts
        for (&name, &addr) in &built_package
            .package
            .compiled_package_info
            .address_alias_instantiation
        {
            // - if we have already seen the (name, addr) pair in dictionary,
            //   do nothing, otherwise,
            // - create an account and register (name, addr) pair with the
            //   designated kind
            address_dict.sync_named_address(
                name,
                addr,
                |_| Ok(()),
                |a| (address_kind, executor.new_account_at(a)),
            )?;
        }

        // derive sender address for this package
        let mut accounts = BTreeSet::new();
        for CompiledUnitWithSource {
            unit,
            source_path: _,
        } in &built_package.package.root_compiled_units
        {
            match unit {
                CompiledUnit::Module(module) => {
                    accounts.insert(module.address);
                },
                CompiledUnit::Script(_) => continue,
            }
        }

        let mut iter = accounts.into_iter();
        let sender_addr = match iter.next() {
            None => {
                // no modules to publish, we are done here
                return Ok(());
            },
            Some(addr) => {
                if iter.next().is_some() {
                    bail!(
                        "[invariant] compiled modules in the same package \
                         cannot belong to different addresses"
                    );
                }
                addr.into_inner()
            },
        };

        // retrieve sender account from the address
        let sender = address_dict.lookup_account(sender_addr).ok_or_else(|| {
            anyhow!(
                "[invariant] unable to find the account \
                 associated with the sender address {sender_addr}"
            )
        })?;

        // prepare the package publish transaction
        let code = built_package.extract_code();
        let metadata = built_package
            .extract_metadata()
            .expect("extracting package metadata must succeed");

        let payload = aptos_stdlib::code_publish_package_txn(
            bcs::to_bytes(&metadata).expect("bcs serialization of package metadata must succeed"),
            code,
        );

        // TODO: set sequence number, gas, and others
        let signed_txn = sender
            .transaction()
            .sequence_number(0)
            .payload(payload)
            .sign();

        // execute the transaction
        let output = executor.execute_transaction(signed_txn);
        log::info!(
            "publishing package {}: status {:?}",
            built_package.name(),
            output.status()
        );

        // done
        Ok(())
    }
}
