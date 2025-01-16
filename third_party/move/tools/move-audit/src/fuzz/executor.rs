use crate::{
    common::PkgDefinition,
    fuzz::account::{AddressRegistry, NamedAddressKind},
};
use anyhow::{anyhow, bail, Result};
use aptos_cached_packages::aptos_stdlib;
use aptos_framework::{BuiltPackage, UPGRADE_POLICY_CUSTOM_FIELD};
use aptos_language_e2e_tests::{
    account::{Account, AccountData},
    data_store::{FakeDataStore, GENESIS_CHANGE_SET_HEAD},
};
use aptos_types::{
    account_config::AccountResource,
    chain_id::ChainId,
    contract_event::ContractEvent,
    on_chain_config::{FeatureFlag, Features, OnChainConfig},
    state_store::{state_key::StateKey, TStateView},
    transaction::TransactionPayload,
};
use move_compiler::compiled_unit::CompiledUnit;
use move_core_types::{
    account_address::AccountAddress, language_storage::StructTag, move_resource::MoveStructType,
};
use move_package::{
    compilation::compiled_package::CompiledUnitWithSource,
    package_hooks::{register_package_hooks, PackageHooks},
    source_package::parsed_manifest::CustomDepInfo,
};
use move_symbol_pool::Symbol;
use serde::de::DeserializeOwned;
use std::collections::BTreeSet;

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

/// A stateful executor
pub struct TracingExecutor {
    /// memory-backed data store
    data_store: FakeDataStore,
    /// event store
    event_store: Vec<ContractEvent>,

    /// address registry
    address_registry: AddressRegistry,
}

impl TracingExecutor {
    /// Create a brand-new executor
    pub fn new() -> Self {
        // create a fake data store with only genesis provisioned
        register_package_hooks(Box::new(AptosPackageHooks {}));

        let mut data_store = FakeDataStore::default();
        data_store.set_chain_id(ChainId::test());
        data_store.add_write_set(GENESIS_CHANGE_SET_HEAD.write_set());

        // pack them
        Self {
            data_store,
            event_store: Vec::new(),
            address_registry: AddressRegistry::new(),
        }
    }

    /// Create an account with no balance of APT
    fn create_account(&mut self, account: Account) {
        let features = Features::fetch_config(&self.data_store).unwrap_or_default();
        let use_fa_balance = features.is_enabled(FeatureFlag::NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE);
        let use_concurrent_balance =
            features.is_enabled(FeatureFlag::DEFAULT_TO_CONCURRENT_FUNGIBLE_BALANCE);

        // provision the account with no balance
        let data = AccountData::with_account(account, 0, 0, use_fa_balance, use_concurrent_balance);
        self.data_store.add_account_data(&data);
    }

    /// Retrieve a resource from data store in raw bytes
    fn read_raw_resource_bytes(
        &self,
        addr: AccountAddress,
        struct_tag: StructTag,
    ) -> Option<Vec<u8>> {
        let value = TStateView::get_state_value(
            &self.data_store,
            &StateKey::resource(&addr, &struct_tag).expect("valid struct tag only"),
        )
        .expect("in-memory data store is not expected to fail");

        // convert value to bytes
        value.map(|v| v.into_bytes().to_vec())
    }

    /// Retrieve a resource from data store in raw bytes
    fn read_typed_resource<T: MoveStructType + DeserializeOwned>(
        &self,
        addr: AccountAddress,
    ) -> Option<T> {
        let bytes = self.read_raw_resource_bytes(addr, T::struct_tag())?;
        let deserialized = bcs::from_bytes(&bytes)
            .expect("serialization expected to succeed (Rust type incompatible with Move type?)");
        Some(deserialized)
    }

    /// Retrieve the account sequence number
    fn get_account_sequence_number(&self, account: &Account) -> u64 {
        let resource: AccountResource = self
            .read_typed_resource(*account.address())
            .expect("provisioned account should have a sequence number");
        resource.sequence_number()
    }

    /// Execute a transaction
    fn execute_transaction(&mut self, sender: AccountAddress, payload: TransactionPayload) {
        // retrieve sender account from the address
        let account = self
            .address_registry
            .lookup_account(sender)
            .unwrap_or_else(|| {
                panic!(
                    "[invariant] unable to find the account \
                     associated with the sender address {sender}"
                )
            });

        account
            .transaction()
            .sequence_number(self.get_account_sequence_number(account))
            .payload(payload)
            .sign();

        // TODO: set gas
    }

    /// Provision a framework package (should already be included in genesis)
    fn provision_framework_package(&mut self, built_package: &BuiltPackage) -> Result<()> {
        // every named address in the framework package will be marked and
        // should remain as a reserved address
        for (&name, &addr) in &built_package
            .package
            .compiled_package_info
            .address_alias_instantiation
        {
            let new_account = self.address_registry.sync_named_address(
                name,
                addr,
                Some(NamedAddressKind::Reserved),
                NamedAddressKind::Reserved,
            )?;
            if let Some(account) = new_account {
                self.create_account(account);
            }
        }

        // we don't need to publish the framework package, so nothing to do
        Ok(())
    }

    /// Provision a regular package
    fn provision_regular_package(
        &mut self,
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
            // - create an account and register the (name, addr) pair with the
            //   designated kind
            let new_account =
                self.address_registry
                    .sync_named_address(name, addr, None, address_kind)?;
            if let Some(account) = new_account {
                self.create_account(account);
            }
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

        // prepare the package publish transaction
        let code = built_package.extract_code();
        let metadata = built_package
            .extract_metadata()
            .expect("extracting package metadata must succeed");

        let payload = aptos_stdlib::code_publish_package_txn(
            bcs::to_bytes(&metadata).expect("bcs serialization of package metadata must succeed"),
            code,
        );

        // execute the transaction
        self.execute_transaction(sender_addr, payload);
        // TODO: not done yet
        log::info!("publishing package {}", built_package.name(),);

        // done
        Ok(())
    }

    /// Provision the executor with a list of pre-compiled modules
    pub fn provision(&mut self, pkgs: &[PkgDefinition]) -> Result<()> {
        // process packages in the order of their dependency chain
        for pkg in pkgs {
            match pkg {
                PkgDefinition::Framework(built_package) => {
                    self.provision_framework_package(built_package)?
                },
                PkgDefinition::Dependency(built_package) => {
                    self.provision_regular_package(NamedAddressKind::Dependency, built_package)?;
                },
                PkgDefinition::Primary(built_package) => {
                    self.provision_regular_package(NamedAddressKind::Primary, built_package)?;
                },
            }
        }

        // done
        Ok(())
    }
}
