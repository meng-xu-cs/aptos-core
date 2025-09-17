// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    deps::{PkgDefinition, PkgKind},
    prep::{
        canvas::{DriverCanvas, LambdaBinding, ScriptSignature},
        datatype::DatatypeRegistry,
        function::{FunctionDecl, FunctionRegistry},
        graph::GraphBuilder,
        ident::FunctionIdent,
        typing::{TypeBase, TypeItem, TypeRef, TypeSubstitution},
    },
};
use itertools::Itertools;
use legacy_move_compiler::compiled_unit::CompiledUnit;
use log::{debug, info};
use move_core_types::ability::AbilitySet;
use move_package::compilation::compiled_package::CompiledUnitWithSource;
use std::{collections::BTreeMap, path::Path};

/// A database that holds information we can statically get from the packages
pub struct Model {
    pub datatype_registry: DatatypeRegistry,
    pub function_registry: FunctionRegistry,
}

impl Model {
    /// Provision the model with a list of packages
    pub fn new(pkgs: &[PkgDefinition]) -> Self {
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
        }
    }

    /// Populate the flow graphs for targeted functions which might be entrypoints
    pub fn populate(
        &self,
        max_trace_depth: usize,
        max_call_repetition: usize,
        script_output_dir: &Path,
    ) -> Vec<ScriptSignature> {
        // initialize the graph builder
        let mut builder = GraphBuilder::new(self, max_trace_depth, max_call_repetition);

        // count primary functions per module
        let mut primary_func_count = 0;
        let mut module_script_counts: BTreeMap<String, usize> = BTreeMap::new();

        // go over all function declarations
        let mut generated_scripts = vec![];
        for decl in self.function_registry.iter_decls() {
            // focus on the primary functions for now
            // TODO(mengxu): in the future we should consider functions in dependencies as well
            if !matches!(decl.kind, PkgKind::Primary) {
                continue;
            }

            primary_func_count += 1;
            let module_key = format!("{}::{}", decl.ident.address(), decl.ident.module_name());
            info!(
                "processing primary function: {} (generics: {}, params: {}, returns: {})",
                decl.ident,
                decl.generics.len(),
                decl.parameters.len(),
                decl.return_sig.len(),
            );

            // try to instantiate the function with identity type arguments with varying ability sets
            let num_combos: usize = decl
                .generics
                .iter()
                .map(|constraint| ability_set_candidates(*constraint).len())
                .product();
            info!("- {num_combos} ability set combinations to explore");

            let scripts_before = generated_scripts.len();

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

                // identify Function-typed params and find matching candidates
                let lambda_params = find_lambda_params(self, decl, &type_args);

                // build per-param candidate lists
                let mut any_param_infeasible = None;
                let mut per_param_candidates = vec![];
                for (idx, fn_params, fn_returns) in lambda_params {
                    let candidates = find_matching_functions(self, &fn_params, &fn_returns);
                    if candidates.is_empty() {
                        any_param_infeasible = Some(idx);
                        break;
                    }
                    per_param_candidates.push((idx, fn_params, candidates));
                }
                if let Some(idx) = any_param_infeasible {
                    debug!("  -> skipping lambda instantiation: no candidates for param {idx}");
                    continue;
                }

                // cartesian product of lambda candidates
                // (if no `Function` params, yields a single empty combination)
                let lambda_combos: Vec<Vec<_>> = if per_param_candidates.is_empty() {
                    vec![vec![]]
                } else {
                    per_param_candidates
                        .iter()
                        .map(|(_, _, candidates)| candidates.iter().enumerate().collect::<Vec<_>>())
                        .multi_cartesian_product()
                        .collect()
                };

                for lambda_combo in lambda_combos {
                    // build the bindings map
                    let mut bindings = BTreeMap::new();
                    for (param_pos, (_, candidate)) in lambda_combo.into_iter().enumerate() {
                        let (param_idx, fn_params, _) = &per_param_candidates[param_pos];
                        let (fn_ident, fn_type_args) = candidate;
                        bindings.insert(*param_idx, LambdaBinding {
                            fn_params: fn_params.clone(),
                            fn_ident: fn_ident.clone(),
                            fn_type_args: fn_type_args.clone(),
                        });
                    }

                    // build flow graphs for this instantiation + lambda combination
                    let raw_graphs = builder.process(decl, &type_args);

                    let raw_count = raw_graphs.len();
                    let mut feasible_count = 0;
                    for graph in raw_graphs {
                        if builder.is_feasible(&graph) {
                            let graph = graph.compact_generics();
                            let canvas = DriverCanvas::build(self, &graph, &bindings);
                            let script = canvas.generate_script(
                                generated_scripts.len(),
                                &decl.ident,
                                script_output_dir,
                            );
                            generated_scripts.push(script);
                            feasible_count += 1;
                        }
                    }
                    debug!(
                        "  -> instantiation produced {raw_count} graphs, {feasible_count} feasible"
                    );
                }
            }

            let scripts_for_func = generated_scripts.len() - scripts_before;
            info!("  -> {scripts_for_func} script(s) for {}", decl.ident);
            *module_script_counts.entry(module_key).or_insert(0) += scripts_for_func;
        }

        // print summary
        info!("========== Script Generation Summary ==========");
        info!("Total primary functions analyzed: {primary_func_count}");
        info!("Total scripts generated: {}", generated_scripts.len());
        info!("Per-module breakdown:");
        for (module, count) in &module_script_counts {
            info!("  {module}: {count} script(s)");
        }
        info!("================================================");

        // done
        generated_scripts
    }
}

/// Identify `Function`-typed parameters in a function instantiation (decl + type args).
///
/// Returns a list of (param_index, fn_params, fn_returns) for each `Function`-typed parameter.
fn find_lambda_params(
    model: &Model,
    decl: &FunctionDecl,
    type_args: &[TypeBase],
) -> Vec<(usize, Vec<TypeItem>, Vec<TypeItem>)> {
    let mut result = vec![];
    for (idx, ty) in decl.parameters.iter().enumerate() {
        let ty_inst = model.datatype_registry.instantiate_type_ref(ty, type_args);

        // extract the base type (unwrapping references)
        let ty_base = match &ty_inst {
            TypeItem::Base(b) | TypeItem::ImmRef(b) | TypeItem::MutRef(b) => b,
        };

        // collect the function type
        match ty_base {
            TypeBase::Function {
                params,
                returns,
                abilities: _,
            } => {
                result.push((idx, params.clone(), returns.clone()));
            },
            _ => continue,
        }
    }
    result
}

/// Find functions whose signature matches the given function type.
///
/// A function matches if:
/// 1. Its parameter count equals fn_params length
/// 2. Its return count equals fn_returns length
/// 3. TypeSubstitution successfully unifies all params and returns
/// 4. All generic type parameters are fully resolved
fn find_matching_functions(
    model: &Model,
    fn_params: &[TypeItem],
    fn_returns: &[TypeItem],
) -> Vec<(FunctionIdent, Vec<TypeBase>)> {
    let mut matches = vec![];

    for decl in model.function_registry.iter_decls() {
        // check arity
        if decl.parameters.len() != fn_params.len() {
            continue;
        }
        if decl.return_sig.len() != fn_returns.len() {
            continue;
        }

        // try to unify params and returns
        let mut unifier = TypeSubstitution::new(&decl.generics);

        let mut ok = true;
        for (decl_param, fn_param) in decl.parameters.iter().zip(fn_params.iter()) {
            if !unify_ref(&mut unifier, decl_param, fn_param) {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }
        for (decl_ret, fn_ret) in decl.return_sig.iter().zip(fn_returns.iter()) {
            if !unify_ref(&mut unifier, decl_ret, fn_ret) {
                ok = false;
                break;
            }
        }
        if !ok {
            continue;
        }

        // check all generics are resolved
        let unified = unifier.finish();
        if unified.iter().any(|u| u.is_none()) {
            continue;
        }

        let type_args: Vec<_> = unified.into_iter().map(|u| u.unwrap()).collect();
        matches.push((decl.ident.clone(), type_args));
    }

    matches
}

/// Unify a TypeRef (from function decl) against a TypeItem (from function type)
fn unify_ref(unifier: &mut TypeSubstitution, decl_ty: &TypeRef, fn_ty: &TypeItem) -> bool {
    match (decl_ty, fn_ty) {
        (TypeRef::Base(tag), TypeItem::Base(base))
        | (TypeRef::ImmRef(tag), TypeItem::ImmRef(base))
        | (TypeRef::MutRef(tag), TypeItem::MutRef(base)) => unifier.unify(tag, base),
        _ => false,
    }
}

// Utility: enumerate ability sets that satisfy the constraints
pub fn ability_set_candidates(constraint: AbilitySet) -> Vec<AbilitySet> {
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
