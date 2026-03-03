// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    common::Account,
    deps::{PkgDefinition, PkgManifest},
    executor::{
        oneshot::{ExecStatus, OneshotFuzzer},
        sequence::{self, ChainFuzzer, DefUseGraph, MAX_CHAIN_FUZZERS},
        tracing::TracingExecutor,
    },
    language::LanguageSetting,
    mutate::mutator::TypePool,
    package,
    prep::model::Model,
};
use anyhow::Result;
use aptos_vm_environment::prod_configs::set_debugging_enabled;
use legacy_move_compiler::compiled_unit::CompiledUnitEnum;
use log::{debug, info};
use move_core_types::{
    ability::AbilitySet,
    identifier::Identifier,
    language_storage::{StructTag, TypeTag as VmTypeTag},
};
use move_vm_runtime::tracing::{clear_tracing_buffer, enable_tracing};
use rand::{rngs::StdRng, SeedableRng};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::PathBuf,
    time::Instant,
};

/// Entrypoint for the fuzzer
pub fn entrypoint(
    pkg_defs: Vec<PkgDefinition>,
    named_accounts: BTreeMap<String, Account>,
    language: LanguageSetting,
    autogen_manifest: PkgManifest,
    cov_trace_path: PathBuf,
    seed: Option<u64>,
    max_trace_depth: usize,
    max_call_repetition: usize,
    num_user_accounts: usize,
    dry_run: bool,
    dict_string: Vec<String>,
    path_fuzz_stats: PathBuf,
    max_chain_length: usize,
    max_chain_repetition: usize,
) -> Result<()> {
    // build a model on the packages
    let model = Model::new(&pkg_defs);
    let generated_scripts = model.populate(
        max_trace_depth,
        max_call_repetition,
        &autogen_manifest.path.join("sources"),
    );
    info!(
        "scripts generated in the autogen package: {}",
        autogen_manifest.path.display()
    );

    if dry_run {
        info!(
            "dry-run mode: generated {} script(s), stopping before fuzzing loop",
            generated_scripts.len()
        );
        return Ok(());
    }

    // compile this autogen module
    let pkg_built = package::build(&autogen_manifest, &named_accounts, language, false)
        .unwrap_or_else(|why| panic!("unable to build the autogen package: {why}"));
    info!("autogen package built successfully");

    let bytecode_version = pkg_built
        .package
        .compiled_package_info
        .build_flags
        .compiler_config
        .bytecode_version;

    // get the scripts
    let mut entrypoints = vec![];
    for unit in pkg_built.package.root_compiled_units {
        match unit.unit {
            CompiledUnitEnum::Module(_) => panic!("unexpected module in the autogen package"),
            CompiledUnitEnum::Script(script) => {
                // lookup the script
                let sig = generated_scripts
                    .iter()
                    .find(|s| s.name == script.name.as_str())
                    .unwrap_or_else(|| {
                        panic!("unable to find a signature for script {}", script.name)
                    });

                // deserialize the script
                let mut code = vec![];
                script
                    .script
                    .serialize_for_version(bytecode_version, &mut code)
                    .unwrap_or_else(|_| panic!("unable to deserialize an autogen CompiledScript"));

                // collect into entrypoints
                entrypoints.push((sig.clone(), code));
            },
        }
    }

    // sanity check that we have all scripts
    assert_eq!(entrypoints.len(), generated_scripts.len());

    // build the type pool from the model
    let type_pool = build_type_pool(&model);

    // enable VM debugging so MOVE_VM_TRACE writes execution traces
    set_debugging_enabled(true);
    enable_tracing(Some(cov_trace_path.to_str().unwrap()));

    // prepare the baseline executor
    let mut executor = TracingExecutor::new();
    for pkg in &pkg_defs {
        executor.add_new_package(pkg)?
    }
    for _ in 0..num_user_accounts {
        executor.add_new_user();
    }

    // scan the full state for resource writes (genesis + provisioning);
    // Mutator::update_object_dict handles the two-pass ObjectGroup filtering
    let initial_resource_writes = executor.scan_all_resource_writes();
    info!(
        "initial state scan found {} resource writes",
        initial_resource_writes.len()
    );

    // clear any trace data accumulated during executor setup (module deployments)
    clear_tracing_buffer();

    //
    // stage 1: per-script fuzzing
    //

    let mut oneshot_fuzzers = vec![];
    // prepare one fuzzer for each script
    for (sig, code) in &entrypoints {
        let mut instance = OneshotFuzzer::new(
            executor.clone(),
            seed.unwrap_or(0),
            sig.clone(),
            code.clone(),
            type_pool.clone(),
            cov_trace_path.clone(),
            dict_string.clone(),
        );
        // seed each fuzzer with initial object discoveries from state scan
        instance.absorb_shared_object_writes(&initial_resource_writes);
        oneshot_fuzzers.push(instance);
    }

    let num_scripts = oneshot_fuzzers.len();
    let seed_val = seed.unwrap_or(0);

    //
    // stage 2: discovery phase - profile resource reads/writes per script
    //
    info!(
        "starting discovery phase ({} scripts)",
        num_scripts
    );
    let profiles = sequence::discover_profiles(
        &executor,
        &entrypoints,
        &type_pool,
        &dict_string,
        seed_val,
        &cov_trace_path,
    );

    // build the Def-Use Graph from discovery profiles
    let dug = DefUseGraph::from_profiles(&profiles);
    info!(
        "DUG: {} type nodes, {} scripts",
        dug.num_types(),
        dug.num_scripts()
    );

    // construct dependency chains via backward DUG traversal
    let mut chain_rng = StdRng::seed_from_u64(seed_val);
    let chains = sequence::construct_chains(
        &dug,
        max_chain_length,
        max_chain_repetition,
        MAX_CHAIN_FUZZERS,
        &mut chain_rng,
    );
    info!("constructed {} chains", chains.len());

    // create chain fuzzers
    let mut chain_fuzzers: Vec<ChainFuzzer> = chains
        .into_iter()
        .map(|chain| {
            let mut cf = ChainFuzzer::new(
                executor.clone(),
                seed_val,
                chain,
                &entrypoints,
                type_pool.clone(),
                cov_trace_path.clone(),
                dict_string.clone(),
            );
            cf.absorb_shared_object_writes(&initial_resource_writes);
            cf
        })
        .collect();
    info!("created {} chain fuzzers", chain_fuzzers.len());

    // clear trace data from discovery phase
    clear_tracing_buffer();

    // startup banner
    eprintln!("=== Move Fuzzer ===");
    eprintln!(
        "scripts: {num_scripts} | chains: {} | seed: {seed_val} | max-depth: {max_trace_depth} | max-chain-len: {max_chain_length}",
        chain_fuzzers.len()
    );
    eprintln!("{}", "-".repeat(72));
    for (i, fuzzer) in oneshot_fuzzers.iter().enumerate() {
        eprintln!("  [{i:3}] {}", fuzzer.script_desc());
    }
    for (i, fuzzer) in chain_fuzzers.iter().enumerate() {
        eprintln!(
            "  [chain:{i:3}] {} (len={})",
            fuzzer.script_short_desc(),
            fuzzer.chain_len()
        );
    }
    eprintln!("{}", "-".repeat(72));
    eprintln!("entering mutation loop...\n");

    let start_time = Instant::now();
    let mut stats = BTreeMap::new();
    let mut category_counts = BTreeMap::new();
    let mut seen_exec_stats = BTreeSet::new();
    let mut iteration = 0u64;
    let mut total_execs = 0u64;
    let mut last_report = Instant::now();
    let mut last_report_coverage = 0usize;

    loop {
        let mut round_writes = vec![];

        // run oneshot fuzzers
        for (idx, fuzzer) in oneshot_fuzzers.iter_mut().enumerate() {
            let (status, corpus_size, found_new, writes) = fuzzer.run_one()?;
            round_writes.extend(writes);
            // update statistics
            *category_counts.entry(status.category()).or_insert(0) += 1;
            *stats.entry(status.to_string()).or_insert(0) += 1;
            total_execs += 1;

            // log new error codes as they are discovered
            if !matches!(status, ExecStatus::Success) && !seen_exec_stats.contains(&status) {
                let desc = fuzzer.script_short_desc();
                info!("[new-status] #{idx} {desc} | {status}");
                seen_exec_stats.insert(status);
            }

            // log new coverage events
            if found_new {
                let desc = fuzzer.script_short_desc();
                let cov = fuzzer.coverage_count();
                info!("[+cov] #{idx} {desc} | corpus: {corpus_size} | coverage: {cov}");
            }
        }

        // run chain fuzzers
        for (idx, fuzzer) in chain_fuzzers.iter_mut().enumerate() {
            let (status, corpus_size, found_new, writes) = fuzzer.run_one()?;
            round_writes.extend(writes);
            *category_counts.entry(status.category()).or_insert(0) += 1;
            *stats.entry(status.to_string()).or_insert(0) += 1;
            total_execs += 1;

            if !matches!(status, ExecStatus::Success) && !seen_exec_stats.contains(&status) {
                let desc = fuzzer.script_short_desc();
                info!("[new-status] chain:{idx} {desc} | {status}");
                seen_exec_stats.insert(status);
            }

            if found_new {
                let desc = fuzzer.script_short_desc();
                let cov = fuzzer.coverage_count();
                info!("[+cov] chain:{idx} {desc} | corpus: {corpus_size} | coverage: {cov}");
            }
        }

        // broadcast new object discoveries to all fuzzers
        if !round_writes.is_empty() {
            for fuzzer in oneshot_fuzzers.iter_mut() {
                fuzzer.absorb_shared_object_writes(&round_writes);
            }
            for fuzzer in chain_fuzzers.iter_mut() {
                fuzzer.absorb_shared_object_writes(&round_writes);
            }
        }

        iteration += 1;

        // report progress every 5 seconds
        if last_report.elapsed().as_secs() >= 5 {
            let elapsed = start_time.elapsed();
            let elapsed_secs = elapsed.as_secs();
            let elapsed_str = fmt_elapsed(elapsed_secs);
            let execs_per_sec = total_execs as f64 / elapsed.as_secs_f64();

            // total corpus and coverage (oneshot + chains)
            let total_corpus: usize = oneshot_fuzzers.iter().map(|f| f.corpus_size()).sum::<usize>()
                + chain_fuzzers.iter().map(|f| f.corpus_size()).sum::<usize>();
            let total_coverage: usize = oneshot_fuzzers.iter().map(|f| f.coverage_count()).sum::<usize>()
                + chain_fuzzers.iter().map(|f| f.coverage_count()).sum::<usize>();
            let coverage_delta = total_coverage.saturating_sub(last_report_coverage);
            let growth_rate = if elapsed_secs > 0 {
                total_coverage as f64 / (elapsed_secs as f64 / 60.0)
            } else {
                0.0
            };

            // header
            debug!(
                "[{elapsed_str}] iter {iteration} | execs: {total_execs} ({execs_per_sec:.1}/s) \
                 | corpus: {total_corpus} | cov: {total_coverage} (+{coverage_delta}) \
                 | growth: {growth_rate:.1}/min"
            );

            // per-script table
            let mut script_json = vec![];
            for (i, fuzzer) in oneshot_fuzzers.iter_mut().enumerate() {
                let desc = fuzzer.script_short_desc();
                let exec = fuzzer.exec_count();
                let corp = fuzzer.corpus_size();
                let cov = fuzzer.coverage_count();
                let delta = fuzzer.coverage_delta_since_report();

                let (hot_marker, last_str) = match fuzzer.last_new_coverage_time() {
                    Some(t) if t.elapsed().as_secs() < 30 => ("*", fmt_ago(t)),
                    Some(t) => (" ", fmt_ago(t)),
                    None => (" ", "-".to_string()),
                };

                let delta_str = if delta > 0 {
                    format!("+{delta:<6}")
                } else {
                    " ".repeat(7)
                };

                debug!(
                    "  {hot_marker}[{i:3}] {desc:<45} exec:{exec:<8} corp:{corp:<5} \
                     cov:{cov:<7} {delta_str} last:{last_str}"
                );

                script_json.push(json!({
                    "index": i,
                    "name": desc,
                    "exec_count": exec,
                    "corpus_size": corp,
                    "coverage_count": cov,
                    "coverage_delta": delta,
                    "last_new_coverage": last_str,
                }));
            }

            // per-chain-fuzzer table
            for (i, fuzzer) in chain_fuzzers.iter_mut().enumerate() {
                let desc = fuzzer.script_short_desc();
                let exec = fuzzer.exec_count();
                let corp = fuzzer.corpus_size();
                let cov = fuzzer.coverage_count();
                let delta = fuzzer.coverage_delta_since_report();
                let clen = fuzzer.chain_len();

                let (hot_marker, last_str) = match fuzzer.last_new_coverage_time() {
                    Some(t) if t.elapsed().as_secs() < 30 => ("*", fmt_ago(t)),
                    Some(t) => (" ", fmt_ago(t)),
                    None => (" ", "-".to_string()),
                };

                let delta_str = if delta > 0 {
                    format!("+{delta:<6}")
                } else {
                    " ".repeat(7)
                };

                debug!(
                    "  {hot_marker}[chain:{i:3}] (len={clen}) {desc:<36} exec:{exec:<8} corp:{corp:<5} \
                     cov:{cov:<7} {delta_str} last:{last_str}"
                );

                script_json.push(json!({
                    "index": format!("chain:{i}"),
                    "name": desc,
                    "chain_length": clen,
                    "exec_count": exec,
                    "corpus_size": corp,
                    "coverage_count": cov,
                    "coverage_delta": delta,
                    "last_new_coverage": last_str,
                }));
            }

            // simplified outcome summary by category
            let outcome_parts: Vec<_> = category_counts
                .iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect();
            debug!(
                "  outcomes: {} | unique: {}",
                outcome_parts.join(" | "),
                seen_exec_stats.len()
            );

            // write JSON stats atomically
            let stats_json = json!({
                "elapsed_secs": elapsed_secs,
                "iteration": iteration,
                "total_execs": total_execs,
                "execs_per_sec": execs_per_sec,
                "total_corpus": total_corpus,
                "total_coverage": total_coverage,
                "coverage_delta": coverage_delta,
                "growth_rate_per_min": growth_rate,
                "scripts": script_json,
                "outcomes": &stats,
                "outcome_categories": &category_counts,
            });
            let tmp_path = path_fuzz_stats.with_added_extension("tmp");
            if let Ok(data) = serde_json::to_string_pretty(&stats_json) {
                let _ = fs::write(&tmp_path, data);
                let _ = fs::rename(&tmp_path, &path_fuzz_stats);
            }

            last_report_coverage = total_coverage;
            last_report = Instant::now();
        }
    }
}

/// Maximum number of instantiations to generate per generic struct
const MAX_INSTANTIATIONS_PER_STRUCT: usize = 8;

/// Build a type pool from the model for generic type argument fuzzing
fn build_type_pool(model: &Model) -> TypePool {
    let mut pool = TypePool::new();

    // step 1: collect concrete candidate types (primitives + non-generic structs)
    let mut candidates: Vec<(VmTypeTag, AbilitySet)> = Vec::new();

    // add all primitive types as candidates
    let primitives = [
        VmTypeTag::Bool,
        VmTypeTag::U8,
        VmTypeTag::U16,
        VmTypeTag::U32,
        VmTypeTag::U64,
        VmTypeTag::U128,
        VmTypeTag::U256,
        VmTypeTag::Address,
    ];
    for prim in &primitives {
        candidates.push((prim.clone(), AbilitySet::PRIMITIVES));
    }

    // add non-generic struct types as candidates
    for decl in model.datatype_registry.iter_decls() {
        if !decl.generics.is_empty() {
            continue;
        }
        let struct_tag = StructTag {
            address: decl.ident.address(),
            module: Identifier::new(decl.ident.module_name()).expect("valid identifier"),
            name: Identifier::new(decl.ident.datatype_name()).expect("valid identifier"),
            type_args: vec![],
        };
        candidates.push((VmTypeTag::Struct(Box::new(struct_tag)), decl.abilities));
    }

    // step 2: add all candidates (and their vector forms) to the pool
    for (ty, abilities) in &candidates {
        pool.add(ty.clone(), *abilities);
        // vector<T> abilities are T's abilities intersected with {copy, drop, store}
        // (vectors can never have `key`)
        let vector_abilities = abilities.intersect(AbilitySet::VECTOR);
        pool.add(VmTypeTag::Vector(Box::new(ty.clone())), vector_abilities);
    }

    // step 3: instantiate generic structs with valid concrete types
    for decl in model.datatype_registry.iter_decls() {
        if decl.generics.is_empty() {
            continue;
        }

        // for each type parameter, find candidates that satisfy its ability constraint
        let per_param_candidates: Vec<Vec<_>> = decl
            .generics
            .iter()
            .map(|(constraint, _is_phantom)| {
                candidates
                    .iter()
                    .filter(|(_, abilities)| constraint.is_subset(*abilities))
                    .collect()
            })
            .collect();

        // skip if any type parameter has no valid candidates
        if per_param_candidates.iter().any(|c| c.is_empty()) {
            continue;
        }

        // generate instantiations by rotating through candidates for each parameter
        let max_candidates = per_param_candidates.iter().map(|c| c.len()).max().unwrap();
        let num_instantiations = max_candidates.min(MAX_INSTANTIATIONS_PER_STRUCT);

        for i in 0..num_instantiations {
            let type_args: Vec<_> = per_param_candidates
                .iter()
                .map(|cands| cands[i % cands.len()].0.clone())
                .collect();

            // compute actual abilities for this instantiation
            let actual_abilities = compute_instantiated_abilities(
                decl.abilities,
                &decl.generics,
                &candidates,
                &type_args,
            );

            let struct_tag = StructTag {
                address: decl.ident.address(),
                module: Identifier::new(decl.ident.module_name()).expect("valid identifier"),
                name: Identifier::new(decl.ident.datatype_name()).expect("valid identifier"),
                type_args,
            };
            pool.add(VmTypeTag::Struct(Box::new(struct_tag)), actual_abilities);
        }
    }

    pool
}

/// Compute the actual abilities of a generic struct instantiated with concrete type arguments
fn compute_instantiated_abilities(
    declared_abilities: AbilitySet,
    generics: &[(AbilitySet, bool)],
    candidates: &[(VmTypeTag, AbilitySet)],
    type_args: &[VmTypeTag],
) -> AbilitySet {
    use move_core_types::ability::Ability;

    // collect abilities of each type argument
    let mut provided_abilities = AbilitySet::ALL;
    for (ty_arg, (_, is_phantom)) in type_args.iter().zip(generics.iter()) {
        if *is_phantom {
            continue;
        }
        let arg_abilities = candidates
            .iter()
            .find(|(ty, _)| ty == ty_arg)
            .map(|(_, a)| *a)
            .unwrap_or(AbilitySet::PRIMITIVES);
        provided_abilities = provided_abilities.intersect(arg_abilities);
    }

    // apply the same logic as derive_actual_ability
    let mut actual_abilities = AbilitySet::EMPTY;
    for ability in Ability::all() {
        if declared_abilities.has_ability(ability)
            && provided_abilities.has_ability(ability.requires())
        {
            actual_abilities = actual_abilities | ability;
        }
    }
    actual_abilities
}

/// Format a Duration as HH:MM:SS
fn fmt_elapsed(secs: u64) -> String {
    let hh = secs / 3600;
    let mm = (secs % 3600) / 60;
    let ss = secs % 60;
    format!("{hh:02}:{mm:02}:{ss:02}")
}

/// Format a duration since an instant as a human-readable "ago" string
fn fmt_ago(since: Instant) -> String {
    let secs = since.elapsed().as_secs();
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else {
        format!("{}h ago", secs / 3600)
    }
}
