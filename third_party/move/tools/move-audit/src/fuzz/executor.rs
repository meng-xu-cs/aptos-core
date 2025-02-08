use crate::{
    common::PkgDefinition,
    fuzz::account::{AddressKind, AddressRegistry, NamedAddressKind},
};
use anyhow::{bail, Result};
use aptos_cached_packages::aptos_stdlib;
use aptos_framework::{BuiltPackage, UPGRADE_POLICY_CUSTOM_FIELD};
use aptos_gas_meter::{StandardGasAlgebra, StandardGasMeter};
use aptos_gas_schedule::{
    AptosGasParameters, FromOnChainGasSchedule, InstructionGasParameters, MiscGasParameters,
    ToOnChainGasSchedule, VMGasParameters,
};
use aptos_language_e2e_tests::{
    account::{Account, AccountData},
    data_store::{FakeDataStore, GENESIS_CHANGE_SET_HEAD},
};
use aptos_types::{
    account_config::{
        AccountResource, CoinInfoResource, ConcurrentSupplyResource, ObjectGroupResource,
    },
    chain_id::ChainId,
    contract_event::ContractEvent,
    on_chain_config::{FeatureFlag, Features, GasScheduleV2, OnChainConfig},
    state_store::{state_key::StateKey, state_value::StateValue, TStateView},
    transaction::{ExecutionStatus, TransactionOutput, TransactionPayload, TransactionStatus},
    write_set::{WriteOp, WriteSetMut},
    AptosCoinType, CoinType,
};
use aptos_vm::{data_cache::AsMoveResolver, AptosVM};
use aptos_vm_environment::environment::AptosEnvironment;
use aptos_vm_logging::log_schema::AdapterLogSchema;
use aptos_vm_types::{
    module_and_script_storage::AsAptosCodeStorage, storage::StorageGasParameters,
};
use move_compiler::compiled_unit::CompiledUnit;
use move_core_types::{
    account_address::AccountAddress, move_resource::MoveResource, vm_status::VMStatus,
};
use move_package::{
    compilation::compiled_package::CompiledUnitWithSource,
    package_hooks::{register_package_hooks, PackageHooks},
    source_package::parsed_manifest::CustomDepInfo,
};
use move_symbol_pool::Symbol;
use serde::{de::DeserializeOwned, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Default APT fund per each new account (10M, with 8 decimals)
const INITIAL_APT_BALANCE: u64 = 1_000_000_000_000_000;

/// Max transaction size in bytes (1MB)
const MAX_TRANSACTION_SIZE_IN_BYTES: u64 = 1024 * 1024;

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

/// Gas consumption profile
enum GasProfile {
    Constant {
        price_per_gas_unit: u64,
        max_gas_units_per_txn: u64,
    },
}

impl GasProfile {
    /// Return gas information needed for transaction
    pub fn get_config_for_txn(&self) -> (u64, u64) {
        match self {
            GasProfile::Constant {
                price_per_gas_unit,
                max_gas_units_per_txn,
            } => (*price_per_gas_unit, *max_gas_units_per_txn),
        }
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

    /// gas profile we are following now
    gas_profile: GasProfile,
}

impl TracingExecutor {
    /// Create a brand-new executor
    pub fn new() -> Self {
        // create a fake data store with only genesis provisioned
        register_package_hooks(Box::new(AptosPackageHooks {}));

        let mut data_store = FakeDataStore::default();
        data_store.set_chain_id(ChainId::test());
        data_store.add_write_set(GENESIS_CHANGE_SET_HEAD.write_set());

        // acquire gas config
        let mut gas_schedule = GasScheduleV2::fetch_config(&data_store)
            .expect("expect genesis to have a gas schedule");
        let mut gas_params = AptosGasParameters::from_on_chain_gas_schedule(
            &gas_schedule.entries.into_iter().collect(),
            gas_schedule.feature_version,
        )
        .unwrap_or_else(|why| panic!("malformed gas schedule: {why}"));

        // actual gas config tweaks
        gas_params.vm.txn.max_transaction_size_in_bytes = MAX_TRANSACTION_SIZE_IN_BYTES.into();

        // update gas config back into storage
        gas_schedule.entries = gas_params.to_on_chain_gas_schedule(gas_schedule.feature_version);
        data_store.set(
            StateKey::on_chain_config::<GasScheduleV2>()
                .expect("expect a valid resource tag for gas schedule"),
            StateValue::from(
                bcs::to_bytes(&gas_schedule)
                    .expect("expect serialization of gas schedule resource to succeed"),
            ),
        );

        // derive the gas profile
        let gas_profile = GasProfile::Constant {
            price_per_gas_unit: gas_params.vm.txn.min_price_per_gas_unit.into(),
            max_gas_units_per_txn: gas_params.vm.txn.maximum_number_of_gas_units.into(),
        };

        // pack them
        Self {
            data_store,
            event_store: Vec::new(),
            address_registry: AddressRegistry::new(),
            gas_profile,
        }
    }

    /// Create an account, and fund it with an initial balance if needed
    fn create_account(&mut self, account: Account, balance: u64) {
        let features =
            Features::fetch_config(&self.data_store).expect("expect features to exist in genesis");
        let use_fa_balance = features.is_enabled(FeatureFlag::NEW_ACCOUNTS_DEFAULT_TO_FA_APT_STORE);
        let use_concurrent_balance =
            features.is_enabled(FeatureFlag::DEFAULT_TO_CONCURRENT_FUNGIBLE_BALANCE);

        // provision the account first
        let data =
            AccountData::with_account(account, balance, 0, use_fa_balance, use_concurrent_balance);
        self.data_store.add_account_data(&data);

        // fund it with new balance
        if let Some(funded_amount) = data.coin_balance() {
            if use_fa_balance {
                assert_eq!(funded_amount, 0);
            } else {
                assert_eq!(funded_amount, balance);
            }

            // fund on the coin side (if needed)
            if funded_amount != 0 {
                let coin_info_resource: CoinInfoResource<AptosCoinType> = self
                    .load_resource(AptosCoinType::coin_info_address())
                    .expect("coin info resource must exist for APT");
                let old_supply: u128 = self
                    .load_value(coin_info_resource.supply_aggregator_state_key())
                    .expect("supply value should exist for APT");
                self.data_store.add_write_set(
                    &coin_info_resource
                        .to_writeset(old_supply + funded_amount as u128)
                        .expect("valid write-set for coin info update"),
                );
            }
        }

        if let Some(funded_amount) = data.fungible_balance() {
            if use_fa_balance {
                assert_eq!(funded_amount, balance);
            } else {
                assert_eq!(funded_amount, 0);
            }

            // fund on the fa side (if needed)
            if funded_amount != 0 {
                // this affects how we fund the account
                assert!(use_concurrent_balance);

                // need to update the total supply
                let mut resource_group: ObjectGroupResource = self
                    .load_resource_group(AccountAddress::TEN)
                    .expect("resource group must exist in data store");

                let mut supply_resource: ConcurrentSupplyResource =
                    Self::load_resource_from_object_group(&resource_group)
                        .expect("concurrent supply exists");

                let new_supply = *supply_resource.current.get() + funded_amount as u128;
                supply_resource.current.set(new_supply);

                Self::store_resource_into_object_group(&mut resource_group, &supply_resource);
                self.store_resource_group(AccountAddress::TEN, &resource_group);
            }
        }

        // log a message
        log::debug!(
            "account {} created with initial balance {balance}",
            data.address()
        );
    }

    /// Retrieve a value from data store and deserialize it
    fn load_value<T: DeserializeOwned>(&self, key: StateKey) -> Option<T> {
        let value = TStateView::get_state_value(&self.data_store, &key)
            .expect("in-memory data store is not expected to fail")?;

        let deserialized = bcs::from_bytes(value.bytes())
            .expect("deserialization expected to succeed (Rust type incompatible with Move type?)");
        Some(deserialized)
    }

    /// Retrieve a resource from data store and deserialize it
    fn load_resource<T: MoveResource>(&self, addr: AccountAddress) -> Option<T> {
        self.load_value(StateKey::resource(&addr, &T::struct_tag()).expect("valid struct tag only"))
    }

    /// Retrieve a resource group from data store and deserialize it
    fn load_resource_group<T: MoveResource>(&self, addr: AccountAddress) -> Option<T> {
        self.load_value(StateKey::resource_group(&addr, &T::struct_tag()))
    }

    /// Store a resource group into data store after serializing it
    fn store_resource_group<T: MoveResource + Serialize>(
        &mut self,
        addr: AccountAddress,
        group: &T,
    ) {
        let write_set = WriteSetMut::new(vec![(
            StateKey::resource_group(
                &addr,
                &T::struct_tag(),
            ),
            WriteOp::legacy_modification(
                bcs::to_bytes(group).expect("serialization expected to succeed (Rust type incompatible with Move type?)").into(),
            )
        )]).freeze().expect("valid write-set");
        self.data_store.add_write_set(&write_set);
    }

    /// Retrieve a resource from an object group resource and deserialize it
    fn load_resource_from_object_group<T: MoveResource>(group: &ObjectGroupResource) -> Option<T> {
        let bytes = group.group.get(&T::struct_tag())?;
        let deserialized = bcs::from_bytes(bytes)
            .expect("deserialization expected to succeed (Rust type incompatible with Move type?)");
        Some(deserialized)
    }

    /// Store a resource into an object group resource after serializing it
    fn store_resource_into_object_group<T: MoveResource + Serialize>(
        group: &mut ObjectGroupResource,
        resource: &T,
    ) {
        let bytes = bcs::to_bytes(resource)
            .expect("serialization expected to succeed (Rust type incompatible with Move type?)");
        group.group.insert(T::struct_tag(), bytes);
    }

    /// Retrieve the account sequence number
    fn get_account_sequence_number(&self, account: &Account) -> u64 {
        let resource: AccountResource = self
            .load_resource(*account.address())
            .expect("provisioned account should have a sequence number");
        resource.sequence_number()
    }

    /// Execute a transaction without committing its output
    fn execute_transaction(
        &mut self,
        sender: AccountAddress,
        payload: TransactionPayload,
    ) -> Result<(VMStatus, TransactionOutput)> {
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

        // construct the transaction
        let (gas_unit_price, max_gas_amount) = self.gas_profile.get_config_for_txn();
        let signed_txn = account
            .transaction()
            .sequence_number(self.get_account_sequence_number(account))
            .gas_unit_price(gas_unit_price)
            .max_gas_amount(max_gas_amount)
            .payload(payload)
            .sign();

        // execute the transaction using our own config of the VM
        let env = AptosEnvironment::new(&self.data_store);
        let vm = AptosVM::new(env.clone(), &self.data_store);
        let resolver = self.data_store.as_move_resolver();
        let code_storage = self.data_store.as_aptos_code_storage(env.clone());
        let log_context = AdapterLogSchema::new(self.data_store.id(), 0);

        let vm_result = vm.execute_user_transaction_with_custom_gas_meter(
            &resolver,
            &code_storage,
            &signed_txn,
            &log_context,
            |gas_feature_version,
             vm_gas_params,
             _,
             is_approved_gov_script,
             meter_balance,
             kill_switch| {
                StandardGasMeter::new(StandardGasAlgebra::new(
                    gas_feature_version,
                    VMGasParameters {
                        misc: MiscGasParameters::zeros(),
                        instr: InstructionGasParameters::zeros(),
                        txn: vm_gas_params.txn,
                    },
                    StorageGasParameters::unlimited(),
                    is_approved_gov_script,
                    meter_balance,
                    kill_switch,
                ))
            },
        );
        match vm_result {
            Ok((status, output, _gas_meter)) => {
                match output.try_materialize_into_transaction_output(&resolver) {
                    Ok(txn_output) => Ok((status, txn_output)),
                    Err(error_status) => {
                        bail!("AptosVM failed unexpectedly with status: {error_status}")
                    },
                }
            },
            Err(error_status) => {
                bail!("AptosVM failed unexpectedly with status: {error_status}");
            },
        }
    }

    /// Execute a transaction with output (if any) committed
    fn execute_transaction_and_commit_output(
        &mut self,
        sender: AccountAddress,
        payload: TransactionPayload,
    ) -> Result<TransactionStatus> {
        let (_vm_status, output) = self.execute_transaction(sender, payload)?;
        let (write_set, events, _gas_used, txn_status, _txn_misc) = output.unpack();
        match txn_status {
            TransactionStatus::Keep(_) => {
                self.data_store.add_write_set(&write_set);
                self.event_store.extend(events);
            },
            TransactionStatus::Discard(_) => {},
            TransactionStatus::Retry => {
                bail!("unexpected retry status for transaction execution");
            },
        }
        Ok(txn_status)
    }

    /// Execute a transaction with output (if any) committed, expect a success
    fn execute_transaction_and_commit_output_expect_success(
        &mut self,
        sender: AccountAddress,
        payload: TransactionPayload,
    ) -> Result<()> {
        let status = self.execute_transaction_and_commit_output(sender, payload)?;
        match status {
            TransactionStatus::Keep(ExecutionStatus::Success) => Ok(()),
            _ => bail!("transaction failed unexpectedly with status: {:?}", status),
        }
    }

    /// Provision a framework package (should already be included in genesis)
    fn provision_framework_package(&mut self, built_package: &BuiltPackage) -> Result<()> {
        // every named address in the framework package will be marked and
        // should remain as a framework address
        for (&name, &addr) in &built_package
            .package
            .compiled_package_info
            .address_alias_instantiation
        {
            let new_account = self.address_registry.sync_named_address(
                name,
                addr,
                Some(NamedAddressKind::Framework),
                NamedAddressKind::Framework,
            )?;
            if let Some(account) = new_account {
                self.create_account(account, INITIAL_APT_BALANCE);
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
        log::debug!("provision package: {}", built_package.name());

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
                self.create_account(account, INITIAL_APT_BALANCE);
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
        self.execute_transaction_and_commit_output_expect_success(sender_addr, payload)?;
        log::debug!("package published: {}", built_package.name());

        // done
        Ok(())
    }

    /// Provision the executor with a pre-compiled package
    pub fn add_new_package(&mut self, pkg: &PkgDefinition) -> Result<()> {
        match pkg {
            PkgDefinition::Framework(built_package) => {
                self.provision_framework_package(built_package)
            },
            PkgDefinition::Dependency(built_package) => {
                self.provision_regular_package(NamedAddressKind::Dependency, built_package)
            },
            PkgDefinition::Primary(built_package) => {
                self.provision_regular_package(NamedAddressKind::Primary, built_package)
            },
        }
    }

    /// Create a new user account in the executor
    pub fn add_new_user(&mut self) {
        let account = self.address_registry.make_user_account();
        self.create_account(account, INITIAL_APT_BALANCE);
    }

    /// Return all addresses known to the executor, sorted by kind
    pub fn all_addresses_by_kind(&self) -> BTreeMap<AddressKind, BTreeSet<AccountAddress>> {
        self.address_registry.all_addresses_by_kind()
    }

    /// Run a transaction with a sender
    pub fn run_payload_with_sender(
        &mut self,
        sender: AccountAddress,
        payload: TransactionPayload,
    ) -> Result<(VMStatus, TransactionOutput)> {
        self.execute_transaction(sender, payload)
    }
}
