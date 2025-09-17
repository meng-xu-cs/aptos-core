// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    account::{AddressKind, AddressRegistry, NamedAddressKind},
    deps::{PkgDefinition, PkgKind},
};
use anyhow::{bail, Result};
use aptos_cached_packages::aptos_stdlib;
use aptos_framework::BuiltPackage;
use aptos_gas_meter::{StandardGasAlgebra, StandardGasMeter};
use aptos_gas_schedule::{
    AptosGasParameters, FromOnChainGasSchedule, InstructionGasParameters, MiscGasParameters,
    ToOnChainGasSchedule, VMGasParameters,
};
use aptos_language_e2e_tests::executor::FakeExecutor;
use aptos_transaction_simulation::{Account, SimulationStateStore};
use aptos_types::{
    access_path::Path,
    account_address::AccountAddress,
    on_chain_config::{GasScheduleV2, OnChainConfig},
    state_store::{
        state_key::{inner::StateKeyInner, StateKey},
        state_value::StateValue,
        TStateView,
    },
    transaction::{
        AuxiliaryInfo, ExecutionStatus, TransactionOutput, TransactionPayload, TransactionStatus,
    },
    vm_status::VMStatus,
};
use aptos_vm::{data_cache::AsMoveResolver, AptosVM};
use aptos_vm_environment::environment::AptosEnvironment;
use aptos_vm_logging::log_schema::AdapterLogSchema;
use aptos_vm_types::{
    module_and_script_storage::AsAptosCodeStorage, storage::StorageGasParameters,
};
use legacy_move_compiler::compiled_unit::CompiledUnit;
use move_core_types::language_storage::StructTag;
use move_package::compilation::compiled_package::CompiledUnitWithSource;
use std::collections::{BTreeMap, BTreeSet};

/// Default APT fund per each new account (10M, with 8 decimals)
const INITIAL_APT_BALANCE: u64 = 1_000_000_000_000_000;

/// Max transaction size in bytes (1MB)
const MAX_TRANSACTION_SIZE_IN_BYTES: u64 = 1024 * 1024;

/// Gas consumption profile
#[derive(Debug, Clone)]
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

/// A resource write extracted from transaction output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceWrite {
    pub address: AccountAddress,
    pub struct_tag: StructTag,
    pub is_resource_group: bool,
}

/// A stateful executor
pub struct TracingExecutor {
    /// backend executor
    executor: FakeExecutor,

    /// address registry
    address_registry: AddressRegistry,

    /// gas profile we are following now
    gas_profile: GasProfile,
}

impl TracingExecutor {
    /// Create a new tracing executor
    pub fn new() -> Self {
        let executor = FakeExecutor::from_head_genesis().set_not_parallel();

        // acquire gas config
        let mut gas_schedule = GasScheduleV2::fetch_config(executor.get_state_view())
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
        executor
            .state_store()
            .set_state_value(
                StateKey::on_chain_config::<GasScheduleV2>()
                    .expect("expect a valid resource tag for gas schedule"),
                StateValue::from(
                    bcs::to_bytes(&gas_schedule)
                        .expect("expect serialization of gas schedule resource to succeed"),
                ),
            )
            .expect("write-back gas configuration");

        // derive the gas profile
        let gas_profile = GasProfile::Constant {
            price_per_gas_unit: gas_params.vm.txn.min_price_per_gas_unit.into(),
            max_gas_units_per_txn: gas_params.vm.txn.maximum_number_of_gas_units.into(),
        };

        // done with the tweaks
        Self {
            executor,
            address_registry: AddressRegistry::new(),
            gas_profile,
        }
    }

    /// Create an account, and fund it with an initial balance if needed
    fn create_account(&mut self, account: Account) {
        self.executor
            .store_and_fund_account(account, INITIAL_APT_BALANCE, 0);
    }

    /// Retrieve the account sequence number
    fn get_account_sequence_number(&self, account: &Account) -> u64 {
        let resource = self
            .executor
            .read_account_resource(account)
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
        let state_view = self.executor.get_state_view();
        let env = AptosEnvironment::new(state_view);
        let vm = AptosVM::new(&env);
        let resolver = state_view.as_move_resolver();
        let code_storage = state_view.as_aptos_code_storage(&env);
        let log_context = AdapterLogSchema::new(state_view.id(), 0);

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
            &AuxiliaryInfo::default(),
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

    /// Extract resource writes from a write set.
    ///
    /// Returns tuples of `(struct_tag, address, is_resource_group)` for each
    /// non-deletion resource or resource group write.
    fn extract_resource_writes(output: &TransactionOutput) -> Vec<ResourceWrite> {
        let mut result = Vec::new();
        for (state_key, _) in output.write_set().write_op_iter() {
            let write = match state_key.inner() {
                StateKeyInner::AccessPath(ap) => match ap.get_path() {
                    Path::Resource(struct_tag) => ResourceWrite {
                        struct_tag,
                        address: ap.address,
                        is_resource_group: false,
                    },
                    Path::ResourceGroup(struct_tag) => ResourceWrite {
                        struct_tag,
                        address: ap.address,
                        is_resource_group: true,
                    },
                    Path::Code(..) => {
                        // we don't care about code publishing
                        continue;
                    },
                },
                StateKeyInner::TableItem { .. } | StateKeyInner::Raw(..) => {
                    // we only care about resource writes, so skip table item and raw bytes
                    continue;
                },
            };
            result.push(write);
        }
        result
    }

    /// Execute a transaction with output (if any) committed
    fn execute_transaction_and_commit_output(
        &mut self,
        sender: AccountAddress,
        payload: TransactionPayload,
    ) -> Result<(VMStatus, TransactionStatus, Vec<ResourceWrite>)> {
        let (vm_status, output) = self.execute_transaction(sender, payload)?;
        let resource_writes = Self::extract_resource_writes(&output);
        let (write_set, events, _gas_used, txn_status, _txn_misc) = output.unpack();
        match txn_status {
            TransactionStatus::Keep(_) => {
                self.executor.apply_write_set(&write_set);
                self.executor.append_events(events);
            },
            TransactionStatus::Discard(_) => {},
            TransactionStatus::Retry => {
                bail!("unexpected retry status for transaction execution");
            },
        }
        Ok((vm_status, txn_status, resource_writes))
    }

    /// Execute a transaction with output (if any) committed, expect a success
    fn execute_transaction_and_commit_output_expect_success(
        &mut self,
        sender: AccountAddress,
        payload: TransactionPayload,
    ) -> Result<()> {
        let (vm_status, txn_status, _resource_writes) =
            self.execute_transaction_and_commit_output(sender, payload)?;
        match txn_status {
            TransactionStatus::Keep(ExecutionStatus::Success) => {
                assert!(matches!(vm_status, VMStatus::Executed));
                Ok(())
            },
            _ => bail!(
                "transaction failed unexpectedly with status: {:?}",
                txn_status
            ),
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
        self.execute_transaction_and_commit_output_expect_success(sender_addr, payload)?;
        log::debug!("package published: {}", built_package.name());

        // done
        Ok(())
    }

    /// Provision the executor with a pre-compiled package
    pub fn add_new_package(&mut self, pkg: &PkgDefinition) -> Result<()> {
        match &pkg.kind {
            PkgKind::Framework => self.provision_framework_package(&pkg.package),
            PkgKind::Dependency => {
                self.provision_regular_package(NamedAddressKind::Dependency, &pkg.package)
            },
            PkgKind::Primary => {
                self.provision_regular_package(NamedAddressKind::Primary, &pkg.package)
            },
        }
    }

    /// Create a new user account in the executor
    pub fn add_new_user(&mut self) {
        let account = self.address_registry.make_user_account();
        self.create_account(account);
    }

    /// Return all addresses known to the executor, sorted by kind
    pub fn all_addresses_by_kind(&self) -> BTreeMap<AddressKind, BTreeSet<AccountAddress>> {
        self.address_registry.all_addresses_by_kind()
    }

    /// Extract all resource writes from the full state store.
    ///
    /// Returns every resource and resource-group entry as a `ResourceWrite`.
    /// The caller (e.g. `Mutator::update_object_dict`) is responsible for
    /// the two-pass ObjectGroup filtering to identify which addresses are
    /// objects and which resources belong to them.
    pub fn scan_all_resource_writes(&self) -> Vec<ResourceWrite> {
        let delta = self.executor.get_state_delta();
        let mut result = Vec::new();
        for (state_key, value_opt) in &delta {
            if value_opt.is_none() {
                continue;
            }
            if let StateKeyInner::AccessPath(ap) = state_key.inner() {
                match ap.get_path() {
                    Path::Resource(struct_tag) => {
                        result.push(ResourceWrite {
                            address: ap.address,
                            struct_tag,
                            is_resource_group: false,
                        });
                    },
                    Path::ResourceGroup(struct_tag) => {
                        result.push(ResourceWrite {
                            address: ap.address,
                            struct_tag,
                            is_resource_group: true,
                        });
                    },
                    Path::Code(..) => {},
                }
            }
        }
        result
    }

    /// Run a transaction with a sender
    pub fn run_payload_with_sender(
        &mut self,
        sender: AccountAddress,
        payload: TransactionPayload,
    ) -> Result<(VMStatus, TransactionStatus, Vec<ResourceWrite>)> {
        self.execute_transaction_and_commit_output(sender, payload)
    }
}

impl Default for TracingExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for TracingExecutor {
    fn clone(&self) -> Self {
        Self {
            executor: self.executor.duplicate_with_assumption(),
            address_registry: self.address_registry.clone(),
            gas_profile: self.gas_profile.clone(),
        }
    }
}
