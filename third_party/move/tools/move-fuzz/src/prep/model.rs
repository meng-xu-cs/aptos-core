// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    deps::{PkgDefinition, PkgKind},
    prep::{
        datatype::DatatypeRegistry, function::FunctionRegistry, graph::FlowGraph, typing::TypeBase,
    },
};
use itertools::Itertools;
use legacy_move_compiler::compiled_unit::CompiledUnit;
use log::debug;
use move_core_types::ability::AbilitySet;
use move_package::compilation::compiled_package::CompiledUnitWithSource;

/// A database that holds information we can statically get from the packages
pub struct Model {
    pub datatype_registry: DatatypeRegistry,
    pub function_registry: FunctionRegistry,
    pub max_trace_depth: usize,
    pub max_call_repetition: usize,
}

impl Model {
    /// Provision the model with a list of packages
    pub fn new(pkgs: &[PkgDefinition], max_trace_depth: usize, max_call_repetition: usize) -> Self {
        // initialize the datatype registry
        let mut datatype_registry = DatatypeRegistry::new();
        for pkg in pkgs {
            let pkg_kind = pkg.kind;
            let pkg_details = &pkg.package.package;
            for CompiledUnitWithSource {
                unit,
                source_path: _,
            } in &pkg_details.root_compiled_units
            {
                let module = match unit {
                    CompiledUnit::Script(_) => continue,
                    CompiledUnit::Module(m) => &m.module,
                };

                // go over all datatypes defined
                datatype_registry.analyze(module, pkg_kind);
            }
            debug!(
                "datatype registry populated for package {}",
                pkg_details.compiled_package_info.package_name
            );
        }

        // initialize the function registry
        let mut function_registry = FunctionRegistry::new();
        for pkg in pkgs {
            let pkg_kind = pkg.kind;
            let pkg_details = &pkg.package.package;
            for CompiledUnitWithSource {
                unit,
                source_path: _,
            } in &pkg_details.root_compiled_units
            {
                let module = match unit {
                    CompiledUnit::Script(_) => continue,
                    CompiledUnit::Module(m) => &m.module,
                };

                // go over all datatypes defined
                function_registry.analyze(&datatype_registry, module, pkg_kind);
            }
            debug!(
                "function registry populated for package {}",
                pkg_details.compiled_package_info.package_name
            );
        }

        // done
        Self {
            datatype_registry,
            function_registry,
            max_trace_depth,
            max_call_repetition,
        }
    }

    /// Populate the flow graphs for targeted functions which might be entrypoints
    pub fn populate(&self) {
        for decl in self.function_registry.iter_decls() {
            // focus on the primary functions for now
            // TODO(mengxu): in the future we should consider functions in dependencies as well
            if !matches!(decl.kind, PkgKind::Primary) {
                continue;
            }

            // try to instantiate the function with empty type arguments
            for combo in decl
                .generics
                .iter()
                .map(|constraint| ability_set_candidates(*constraint))
                .multi_cartesian_product()
            {
                assert_eq!(combo.len(), decl.generics.len());
                let type_args: Vec<_> = combo
                    .into_iter()
                    .enumerate()
                    .map(|(index, abilities)| TypeBase::Param { index, abilities })
                    .collect();

                // analyze and generate flow graphs for this instantiation
                FlowGraph::analyze(self, decl, &type_args);
            }
        }
    }
}

// Utility: enumerate ability sets that satisfy the constraints
fn ability_set_candidates(constraint: AbilitySet) -> Vec<AbilitySet> {
    (AbilitySet::ALL.setminus(constraint))
        .into_iter()
        .powerset()
        .map(|set| {
            let mut combined = constraint;
            for ability in set {
                combined = combined.add(ability);
            }
            combined
        })
        .collect()
}
