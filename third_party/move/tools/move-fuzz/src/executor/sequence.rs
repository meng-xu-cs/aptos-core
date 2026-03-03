// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    executor::{
        oneshot::ExecStatus,
        tracing::{ResourceRead, ResourceWrite, TracingExecutor},
    },
    mutate::mutator::{Mutator, TypePool},
    prep::canvas::{BasicInput, ScriptSignature},
};
use aptos_types::account_address::AccountAddress;
use anyhow::Result;
use aptos_types::transaction::{
    ExecutionStatus, Script, TransactionArgument, TransactionPayload, TransactionStatus,
};
use log::debug;
use move_core_types::{
    language_storage::{StructTag, TypeTag as VmTypeTag},
    value::MoveValue,
    vm_status::VMStatus,
};
use move_coverage::coverage_map::{CoverageMap, ExecCoverageMap, ModuleCoverageMap};
use move_vm_runtime::tracing::{clear_tracing_buffer, flush_tracing_buffer};
use rand::{rngs::StdRng, Rng};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Instant,
};

/// Maximum number of chain fuzzers to create
pub const MAX_CHAIN_FUZZERS: usize = 50;

/// Number of discovery runs per script during profiling
const NUM_DISCOVERY_RUNS: usize = 10;

// ---------------------------------------------------------------------------
// Resource tagging and script profiling (kept from original)
// ---------------------------------------------------------------------------

/// A resource type identifier for def-use matching (ignores storage address)
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ResourceTag {
    pub struct_tag: StructTag,
}

/// Per-script resource access profile
pub struct ScriptProfile {
    pub script_index: usize,
    pub reads: BTreeSet<ResourceTag>,
    pub writes: BTreeSet<ResourceTag>,
    pub ever_succeeded: bool,
}

/// Resource profile from a single execution that found new coverage.
/// Used to feed per-seed observations back into the DUG.
#[derive(Clone)]
pub struct ExecResourceProfile {
    pub script_index: usize,
    pub reads: BTreeSet<ResourceTag>,
    pub writes: BTreeSet<ResourceTag>,
    pub succeeded: bool,
}

impl ExecResourceProfile {
    /// Build from raw execution outputs, applying framework address filtering.
    ///
    /// Reads are always recorded (filtering out framework address 0x1).
    /// Writes are only recorded when `succeeded` is true.
    /// This matches the convention in `discover_profiles()`.
    pub fn from_execution(
        script_index: usize,
        resource_writes: &[ResourceWrite],
        resource_reads: &[ResourceRead],
        succeeded: bool,
    ) -> Self {
        let mut reads = BTreeSet::new();
        for read in resource_reads {
            if read.address == AccountAddress::ONE {
                continue;
            }
            reads.insert(ResourceTag {
                struct_tag: read.struct_tag.clone(),
            });
        }

        let mut writes = BTreeSet::new();
        if succeeded {
            for write in resource_writes {
                writes.insert(ResourceTag {
                    struct_tag: write.struct_tag.clone(),
                });
            }
        }

        Self {
            script_index,
            reads,
            writes,
            succeeded,
        }
    }
}

/// Discover resource access profiles for each script by running them
/// multiple times with random inputs
pub fn discover_profiles(
    base_executor: &TracingExecutor,
    entrypoints: &[(ScriptSignature, Vec<u8>)],
    type_pool: &TypePool,
    dict_string: &[String],
    seed: u64,
    _trace_path: &Path,
) -> Vec<ScriptProfile> {
    let mut profiles = Vec::with_capacity(entrypoints.len());

    for (idx, (sig, code)) in entrypoints.iter().enumerate() {
        let mut executor = base_executor.clone();
        let mut mutator = Mutator::new(
            seed.wrapping_add(idx as u64),
            executor.all_addresses_by_kind(),
            type_pool.clone(),
            dict_string.to_vec(),
        );

        let mut all_reads = BTreeSet::new();
        let mut all_writes = BTreeSet::new();
        let mut ever_succeeded = false;

        for _ in 0..NUM_DISCOVERY_RUNS {
            let sender = mutator.random_signer();

            let non_signer_params: Vec<_> = sig
                .parameters
                .iter()
                .filter(|ty| !matches!(ty, BasicInput::Signer))
                .collect();

            let ty_args = mutator.random_type_args(&sig.generics);
            let args: Vec<MoveValue> = non_signer_params
                .iter()
                .map(|ty| mutator.random_value(ty))
                .collect();

            let payload = TransactionPayload::Script(Script::new(
                code.clone(),
                ty_args,
                args.iter()
                    .map(|arg| {
                        TransactionArgument::Serialized(
                            MoveValue::simple_serialize(arg).expect("arguments must serialize"),
                        )
                    })
                    .collect(),
            ));

            // clear trace buffer before discovery run
            clear_tracing_buffer();

            let result = executor.run_payload_with_sender_tracking(sender, payload);

            // flush trace buffer after discovery run
            flush_tracing_buffer();

            if let Ok((vm_status, txn_status, resource_writes, resource_reads)) = result {
                // collect reads (filter framework address 0x1)
                for read in &resource_reads {
                    if read.address == aptos_types::account_address::AccountAddress::ONE {
                        continue;
                    }
                    all_reads.insert(ResourceTag {
                        struct_tag: read.struct_tag.clone(),
                    });
                }

                // collect writes only from successful executions
                let is_success = matches!(
                    (&vm_status, &txn_status),
                    (VMStatus::Executed, TransactionStatus::Keep(ExecutionStatus::Success))
                );
                if is_success {
                    ever_succeeded = true;
                    for write in &resource_writes {
                        all_writes.insert(ResourceTag {
                            struct_tag: write.struct_tag.clone(),
                        });
                    }
                }
            }
        }

        profiles.push(ScriptProfile {
            script_index: idx,
            reads: all_reads,
            writes: all_writes,
            ever_succeeded,
        });
    }

    profiles
}

// ---------------------------------------------------------------------------
// Def-Use Graph (DUG)
// ---------------------------------------------------------------------------

/// A bipartite Def-Use Graph of global state.
///
/// Nodes are either **type nodes** (resource types) or **script nodes** (by index).
/// Edges are:
/// - **Def** (script → type): the script writes (defines) this resource type
/// - **Use** (type → script): the script reads (uses) this resource type
pub struct DefUseGraph {
    num_scripts: usize,

    /// All distinct ResourceTag values observed across all profiles
    type_nodes: Vec<ResourceTag>,

    /// ResourceTag → type node index (for fast lookup)
    type_index: BTreeMap<ResourceTag, usize>,

    /// script_index → set of type node indices this script writes
    /// (only populated for scripts that ever_succeeded)
    defs: Vec<BTreeSet<usize>>,

    /// script_index → set of type node indices this script reads
    uses: Vec<BTreeSet<usize>>,

    /// type_node_index → set of script indices that produce (write) it
    producers: BTreeMap<usize, BTreeSet<usize>>,

    /// Which scripts ever succeeded during discovery
    ever_succeeded: BTreeSet<usize>,

    /// Monotonic modification counter for change detection
    modification_count: usize,
}

impl DefUseGraph {
    /// Build a DUG from discovery profiles.
    pub fn from_profiles(profiles: &[ScriptProfile]) -> Self {
        let num_scripts = profiles.len();
        let mut type_nodes = Vec::new();
        let mut type_index = BTreeMap::new();

        // Helper: get-or-insert a type node index for a ResourceTag
        let mut intern_type = |tag: &ResourceTag| -> usize {
            if let Some(&idx) = type_index.get(tag) {
                idx
            } else {
                let idx = type_nodes.len();
                type_nodes.push(tag.clone());
                type_index.insert(tag.clone(), idx);
                idx
            }
        };

        let mut defs = vec![BTreeSet::new(); num_scripts];
        let mut uses = vec![BTreeSet::new(); num_scripts];
        let mut ever_succeeded = BTreeSet::new();

        for profile in profiles {
            let si = profile.script_index;

            // Always record uses (reads)
            for tag in &profile.reads {
                let ti = intern_type(tag);
                uses[si].insert(ti);
            }

            // Only record defs (writes) for scripts that succeeded
            if profile.ever_succeeded {
                ever_succeeded.insert(si);
                for tag in &profile.writes {
                    let ti = intern_type(tag);
                    defs[si].insert(ti);
                }
            }
        }

        // Build reverse index: type → producing scripts
        let mut producers: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
        for (si, def_set) in defs.iter().enumerate() {
            for &ti in def_set {
                producers.entry(ti).or_default().insert(si);
            }
        }

        Self {
            num_scripts,
            type_nodes,
            type_index,
            defs,
            uses,
            producers,
            ever_succeeded,
            modification_count: 0,
        }
    }

    /// Type node indices that a script reads (uses)
    pub fn uses_of(&self, script_index: usize) -> &BTreeSet<usize> {
        &self.uses[script_index]
    }

    /// Type node indices that a script writes (defines)
    pub fn defs_of(&self, script_index: usize) -> &BTreeSet<usize> {
        &self.defs[script_index]
    }

    /// Scripts that produce (write) a given type node
    pub fn producers_of(&self, type_node: usize) -> &BTreeSet<usize> {
        static EMPTY: BTreeSet<usize> = BTreeSet::new();
        self.producers.get(&type_node).unwrap_or(&EMPTY)
    }

    /// Whether a script ever succeeded during discovery profiling
    pub fn script_ever_succeeded(&self, script_index: usize) -> bool {
        self.ever_succeeded.contains(&script_index)
    }

    /// Unmet dependencies: types a script reads but does NOT itself write
    pub fn unmet_deps(&self, script_index: usize) -> BTreeSet<usize> {
        self.uses[script_index]
            .difference(&self.defs[script_index])
            .copied()
            .collect()
    }

    /// Number of distinct resource type nodes in the DUG
    pub fn num_types(&self) -> usize {
        self.type_nodes.len()
    }

    /// Number of script nodes in the DUG
    pub fn num_scripts(&self) -> usize {
        self.num_scripts
    }

    /// Get the ResourceTag for a type node index
    #[cfg(test)]
    pub fn type_tag(&self, type_node: usize) -> &ResourceTag {
        &self.type_nodes[type_node]
    }

    // -----------------------------------------------------------------------
    // Mutation methods (for dynamic DUG updates)
    // -----------------------------------------------------------------------

    /// Intern a ResourceTag, returning its type node index.
    /// Creates a new type node if the tag hasn't been seen before.
    fn intern_type(&mut self, tag: &ResourceTag) -> usize {
        if let Some(&idx) = self.type_index.get(tag) {
            idx
        } else {
            let idx = self.type_nodes.len();
            self.type_nodes.push(tag.clone());
            self.type_index.insert(tag.clone(), idx);
            idx
        }
    }

    /// Add a def edge: script `script_index` writes `tag`.
    /// Returns true if the edge was new (DUG changed).
    pub fn add_def(&mut self, script_index: usize, tag: &ResourceTag) -> bool {
        assert!(script_index < self.num_scripts);
        let ti = self.intern_type(tag);
        let inserted = self.defs[script_index].insert(ti);
        if inserted {
            self.producers.entry(ti).or_default().insert(script_index);
            self.modification_count += 1;
        }
        inserted
    }

    /// Add a use edge: script `script_index` reads `tag`.
    /// Returns true if the edge was new (DUG changed).
    pub fn add_use(&mut self, script_index: usize, tag: &ResourceTag) -> bool {
        assert!(script_index < self.num_scripts);
        let ti = self.intern_type(tag);
        let inserted = self.uses[script_index].insert(ti);
        if inserted {
            self.modification_count += 1;
        }
        inserted
    }

    /// Mark a script as having succeeded at least once.
    /// Returns true if this is the first time the script succeeded.
    pub fn mark_succeeded(&mut self, script_index: usize) -> bool {
        assert!(script_index < self.num_scripts);
        let inserted = self.ever_succeeded.insert(script_index);
        if inserted {
            self.modification_count += 1;
        }
        inserted
    }

    /// Ingest an ExecResourceProfile into the DUG.
    /// Adds use edges for all reads, and def edges + mark_succeeded for
    /// successful writes.
    pub fn ingest_profile(&mut self, profile: &ExecResourceProfile) {
        for tag in &profile.reads {
            self.add_use(profile.script_index, tag);
        }
        if profile.succeeded {
            self.mark_succeeded(profile.script_index);
            for tag in &profile.writes {
                self.add_def(profile.script_index, tag);
            }
        }
    }

    /// Check if the DUG has been modified since a given marker value.
    /// Pass the return value of `modification_marker()` at a previous point.
    pub fn has_changed_since(&self, marker: usize) -> bool {
        self.modification_count > marker
    }

    /// Get the current modification marker (for use with `has_changed_since()`).
    pub fn modification_marker(&self) -> usize {
        self.modification_count
    }

    /// Look up the type node index for a ResourceTag.
    pub fn type_index_of(&self, tag: &ResourceTag) -> Option<&usize> {
        self.type_index.get(tag)
    }

    /// Scripts that consume (read) a given type node.
    ///
    /// Only called during periodic reconstruction, not in the hot loop,
    /// so linear iteration over all scripts is acceptable.
    pub fn consumers_of(&self, type_node: usize) -> BTreeSet<usize> {
        (0..self.num_scripts)
            .filter(|&si| self.uses[si].contains(&type_node))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Chain: an ordered sequence of script indices
// ---------------------------------------------------------------------------

/// A dependency chain: an ordered sequence of scripts to execute.
/// `steps[0]` runs first (deepest dependency), `steps[last]` is the target.
#[derive(Debug, Clone)]
pub struct Chain {
    pub steps: Vec<usize>,
}

impl Chain {
    /// The target script (last in the chain)
    pub fn target(&self) -> usize {
        *self.steps.last().expect("chain must be non-empty")
    }

    /// Number of steps in the chain
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the chain is empty
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Sequence Database
// ---------------------------------------------------------------------------

/// A stored sequence: the chain steps + the seed inputs that produced new coverage.
#[derive(Clone)]
pub struct SequenceEntry {
    /// Unique monotonic identifier
    pub id: u64,
    /// Ordered script indices (same semantics as Chain.steps)
    pub steps: Vec<usize>,
    /// Per-step (type_args, value_args) — len == steps.len()
    pub seed: Vec<(Vec<VmTypeTag>, Vec<MoveValue>)>,
    /// Resource types written by the whole sequence (union of all step writes)
    pub produced_types: BTreeSet<ResourceTag>,
    /// Resource types read by the whole sequence (union of all step reads)
    pub consumed_types: BTreeSet<ResourceTag>,
    /// Whether all steps succeeded
    pub all_succeeded: bool,
}

/// Central store of coverage-producing multi-transaction sequences.
///
/// Provides:
/// 1. Cross-fuzzer seed sharing via prefix matching
/// 2. Sequence extension proposals based on DUG connectivity
pub struct SequenceDb {
    entries: Vec<SequenceEntry>,
    next_id: u64,
}

/// Probability of drawing a seed from the SequenceDb instead of local corpus
const SEQ_DB_PROB: u8 = 20;

impl Default for SequenceDb {
    fn default() -> Self {
        Self::new()
    }
}

impl SequenceDb {
    /// Create a new empty sequence database
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_id: 0,
        }
    }

    /// Add an entry from a ChainFuzzer coverage discovery.
    ///
    /// `steps` and `seed` come from the chain fuzzer, `profiles` are the
    /// per-step ExecResourceProfiles generated when new coverage was found.
    /// Returns the entry's unique ID.
    pub fn add_entry(
        &mut self,
        steps: Vec<usize>,
        seed: Vec<(Vec<VmTypeTag>, Vec<MoveValue>)>,
        profiles: &[ExecResourceProfile],
    ) -> u64 {
        assert_eq!(steps.len(), seed.len());

        let mut produced_types = BTreeSet::new();
        let mut consumed_types = BTreeSet::new();
        let mut all_succeeded = true;

        for p in profiles {
            produced_types.extend(p.writes.iter().cloned());
            consumed_types.extend(p.reads.iter().cloned());
            if !p.succeeded {
                all_succeeded = false;
            }
        }

        let id = self.next_id;
        self.next_id += 1;

        self.entries.push(SequenceEntry {
            id,
            steps,
            seed,
            produced_types,
            consumed_types,
            all_succeeded,
        });

        id
    }

    /// Find all entries whose `steps` are a prefix of (or equal to) `chain_steps`.
    pub fn find_prefix_seeds(&self, chain_steps: &[usize]) -> Vec<&SequenceEntry> {
        self.entries
            .iter()
            .filter(|e| {
                e.steps.len() <= chain_steps.len()
                    && e.steps.as_slice() == &chain_steps[..e.steps.len()]
            })
            .collect()
    }

    /// Count prefix-compatible entries for a given chain.
    pub fn prefix_compatible_count(&self, chain_steps: &[usize]) -> usize {
        self.entries
            .iter()
            .filter(|e| {
                e.steps.len() <= chain_steps.len()
                    && e.steps.as_slice() == &chain_steps[..e.steps.len()]
            })
            .count()
    }

    /// Pick a random prefix-compatible entry's seed, truncated to the prefix length.
    pub fn pick_prefix_seed(
        &self,
        chain_steps: &[usize],
        rng: &mut StdRng,
    ) -> Option<Vec<(Vec<VmTypeTag>, Vec<MoveValue>)>> {
        let compatible: Vec<_> = self.find_prefix_seeds(chain_steps);
        if compatible.is_empty() {
            return None;
        }
        let entry = compatible[rng.gen_range(0, compatible.len())];
        // Return seed truncated to the prefix length
        Some(entry.seed[..entry.steps.len()].to_vec())
    }

    /// Propose sequence extensions by appending DUG-linked consumers.
    ///
    /// For each all-succeeded entry shorter than `max_chain_length`, finds scripts
    /// that consume types produced by the sequence and creates extended chains.
    /// Returns `(extended_chain, parent_seed)` pairs (max `max_extensions`).
    pub fn propose_extensions(
        &self,
        dug: &DefUseGraph,
        max_chain_length: usize,
        max_extensions: usize,
    ) -> Vec<(Chain, Vec<(Vec<VmTypeTag>, Vec<MoveValue>)>)> {
        let mut extensions = Vec::new();

        for entry in &self.entries {
            if !entry.all_succeeded || entry.steps.len() >= max_chain_length {
                continue;
            }

            for tag in &entry.produced_types {
                if let Some(&ti) = dug.type_index_of(tag) {
                    for consumer in dug.consumers_of(ti) {
                        // Don't add a script that's already in the chain
                        if entry.steps.contains(&consumer) {
                            continue;
                        }

                        let mut ext_steps = entry.steps.clone();
                        ext_steps.push(consumer);
                        extensions.push((
                            Chain { steps: ext_steps },
                            entry.seed.clone(),
                        ));

                        if extensions.len() >= max_extensions {
                            return extensions;
                        }
                    }
                }
            }
        }

        extensions
    }

    /// Total number of entries in the database
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Chain construction
// ---------------------------------------------------------------------------

/// Construct dependency chains from the DUG.
///
/// For each target script that has unmet dependencies, build a chain by backward
/// traversal of the DUG. Targets are prioritized: never-succeeded scripts first,
/// then by number of unmet dependencies (more = more interesting).
pub fn construct_chains(
    dug: &DefUseGraph,
    max_chain_length: usize,
    max_repetition: usize,
    max_chains: usize,
    rng: &mut StdRng,
) -> Vec<Chain> {
    let mut chains = Vec::new();

    // Collect and prioritize targets
    let mut targets: Vec<usize> = (0..dug.num_scripts()).collect();
    targets.sort_by(|a, b| {
        let a_failed = !dug.script_ever_succeeded(*a);
        let b_failed = !dug.script_ever_succeeded(*b);
        // Never-succeeded scripts first, then by number of unmet deps (descending)
        b_failed.cmp(&a_failed).then_with(|| {
            let a_unmet = dug.unmet_deps(*a).len();
            let b_unmet = dug.unmet_deps(*b).len();
            b_unmet.cmp(&a_unmet)
        })
    });

    for &target in &targets {
        if chains.len() >= max_chains {
            break;
        }

        // Only build chains for scripts with unmet dependencies
        let unmet = dug.unmet_deps(target);
        if unmet.is_empty() {
            continue;
        }

        if let Some(chain) = build_one_chain(dug, target, max_chain_length, max_repetition, rng) {
            debug!(
                "chain for target {}: [{}] (length {})",
                target,
                chain
                    .steps
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                chain.len(),
            );
            chains.push(chain);
        }
    }

    chains
}

/// Build one chain ending at `target` by backward greedy traversal of the DUG.
///
/// Algorithm:
/// 1. Start with `chain_reversed = [target]` and `resolved_types = defs_of(target)`
/// 2. Queue all unmet dependencies (types target reads but doesn't write)
/// 3. While queue non-empty and chain length < max_length:
///    - Pop a needed type (random for variety)
///    - Find a producer, preferring scripts that have succeeded (70/30 bias)
///    - Add producer to chain, mark its defs as resolved, enqueue its unmet deps
/// 4. Reverse to get execution order (producers first, target last)
fn build_one_chain(
    dug: &DefUseGraph,
    target: usize,
    max_length: usize,
    max_repetition: usize,
    rng: &mut StdRng,
) -> Option<Chain> {
    let mut chain_reversed: Vec<usize> = vec![target];
    let mut resolved_types: BTreeSet<usize> = dug.defs_of(target).clone();

    // Track how many times each script appears in the chain (for repetition limit)
    let mut occurrence_count: BTreeMap<usize, usize> = BTreeMap::new();
    *occurrence_count.entry(target).or_insert(0) += 1;

    // Queue of type node indices whose dependencies need resolving
    let mut queue: Vec<usize> = dug.unmet_deps(target).into_iter().collect();

    while !queue.is_empty() && chain_reversed.len() < max_length {
        // Pick a needed type from the queue (random selection for variety)
        let queue_idx = rng.gen_range(0, queue.len());
        let needed_type = queue.swap_remove(queue_idx);

        // Skip if this type was resolved while processing other dependencies
        if resolved_types.contains(&needed_type) {
            continue;
        }

        // Find producers for this type
        let producers = dug.producers_of(needed_type);
        if producers.is_empty() {
            // No producer exists — this dependency cannot be resolved
            continue;
        }

        // Filter by repetition limit
        let eligible: Vec<usize> = producers
            .iter()
            .copied()
            .filter(|&p| occurrence_count.get(&p).copied().unwrap_or(0) < max_repetition)
            .collect();

        if eligible.is_empty() {
            continue;
        }

        // Sort candidates: prefer scripts that have ever succeeded
        let mut candidates = eligible;
        candidates.sort_by(|a, b| {
            let a_ok = dug.script_ever_succeeded(*a);
            let b_ok = dug.script_ever_succeeded(*b);
            b_ok.cmp(&a_ok) // true (succeeded) sorts first
        });

        // Pick a producer (70% chance of picking the best, 30% random)
        let pick_idx = if candidates.len() > 1 && rng.gen_range(0u8, 100) >= 70 {
            rng.gen_range(0, candidates.len())
        } else {
            0
        };
        let producer = candidates[pick_idx];

        // Add producer to chain
        chain_reversed.push(producer);
        *occurrence_count.entry(producer).or_insert(0) += 1;

        // Update resolved types with the producer's defs
        resolved_types.extend(dug.defs_of(producer).iter());

        // Enqueue the producer's unmet dependencies
        for &t in dug.uses_of(producer) {
            if !resolved_types.contains(&t) && !queue.contains(&t) {
                queue.push(t);
            }
        }
    }

    // Only return if we added at least one predecessor
    if chain_reversed.len() <= 1 {
        return None;
    }

    // Reverse: producers first, target last
    chain_reversed.reverse();
    Some(Chain {
        steps: chain_reversed,
    })
}

// ---------------------------------------------------------------------------
// ChainFuzzer: generalized sequence executor for arbitrary-length chains
// ---------------------------------------------------------------------------

/// A chain fuzzer that executes an ordered sequence of scripts (arbitrary length).
///
/// Replaces the pair-only `SequenceFuzzer`. A chain of length 2 is equivalent to
/// the old predecessor→successor pair.
pub struct ChainFuzzer {
    /// The chain this fuzzer executes
    chain: Chain,

    /// Per-step script signatures
    step_sigs: Vec<ScriptSignature>,

    /// Per-step compiled bytecode
    step_codes: Vec<Vec<u8>>,

    /// Per-step mutators (independently seeded)
    mutators: Vec<Mutator>,

    /// Execution state (independent clone per fuzzer)
    executor: TracingExecutor,

    /// Path to the coverage trace file
    trace_path: PathBuf,

    /// Accumulated coverage map
    coverage: ExecCoverageMap,

    /// Corpus: each seed stores per-step (type_args, value_args)
    seedpool: Vec<Vec<(Vec<VmTypeTag>, Vec<MoveValue>)>>,

    // Statistics
    exec_count: u64,
    last_new_coverage_time: Option<Instant>,
    coverage_at_last_report: usize,
}

impl ChainFuzzer {
    /// Create a new chain fuzzer
    pub fn new(
        executor: TracingExecutor,
        seed: u64,
        chain: Chain,
        entrypoints: &[(ScriptSignature, Vec<u8>)],
        type_pool: TypePool,
        trace_path: PathBuf,
        dict_string: Vec<String>,
    ) -> Self {
        let addresses = executor.all_addresses_by_kind();
        let step_sigs: Vec<_> = chain
            .steps
            .iter()
            .map(|&idx| entrypoints[idx].0.clone())
            .collect();
        let step_codes: Vec<_> = chain
            .steps
            .iter()
            .map(|&idx| entrypoints[idx].1.clone())
            .collect();
        let mutators: Vec<_> = chain
            .steps
            .iter()
            .enumerate()
            .map(|(i, _)| {
                Mutator::new(
                    seed.wrapping_add(i as u64),
                    addresses.clone(),
                    type_pool.clone(),
                    dict_string.clone(),
                )
            })
            .collect();

        Self {
            chain,
            step_sigs,
            step_codes,
            mutators,
            executor,
            trace_path,
            coverage: ExecCoverageMap::new(String::new()),
            seedpool: vec![],
            exec_count: 0,
            last_new_coverage_time: None,
            coverage_at_last_report: 0,
        }
    }

    /// Get a human-readable description of the chain
    pub fn script_desc(&self) -> String {
        self.step_sigs
            .iter()
            .map(|sig| sig.ident.to_string())
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    /// Get a short description: `mod::fn -> mod::fn -> ...`
    pub fn script_short_desc(&self) -> String {
        self.step_sigs
            .iter()
            .map(|sig| {
                format!(
                    "{}::{}",
                    sig.ident.module_name(),
                    sig.ident.function_name()
                )
            })
            .collect::<Vec<_>>()
            .join(" -> ")
    }

    /// Get the current corpus (seed pool) size
    pub fn corpus_size(&self) -> usize {
        self.seedpool.len()
    }

    /// Get the total number of covered bytecode positions across all modules
    pub fn coverage_count(&self) -> usize {
        self.coverage
            .module_maps
            .values()
            .flat_map(|m| m.function_maps.values())
            .map(|f| f.len())
            .sum()
    }

    /// Get the total number of executions
    pub fn exec_count(&self) -> u64 {
        self.exec_count
    }

    /// Get when coverage was last found
    pub fn last_new_coverage_time(&self) -> Option<Instant> {
        self.last_new_coverage_time
    }

    /// Get the coverage delta since last report and reset the snapshot
    pub fn coverage_delta_since_report(&mut self) -> usize {
        let current = self.coverage_count();
        let delta = current.saturating_sub(self.coverage_at_last_report);
        self.coverage_at_last_report = current;
        delta
    }

    /// Get the chain length
    pub fn chain_len(&self) -> usize {
        self.chain.len()
    }

    /// Get the chain's steps (for deduplication when reconstructing chains)
    pub fn chain_steps(&self) -> &[usize] {
        &self.chain.steps
    }

    /// Execute one chain iteration.
    ///
    /// Returns `(exec_status, corpus_size, found_new_coverage, resource_writes, profiles, seed_clone)`.
    /// - `exec_status` is the status of the last step that executed (or the first failure)
    /// - Resource writes are accumulated from all successful steps
    /// - `profiles` contains per-step resource profiles when new coverage was found
    /// - `seed_clone` is a copy of the coverage-producing seed (for SequenceDb), or None
    ///
    /// When `seq_db` is provided, there is a chance (SEQ_DB_PROB = 20%) that inputs
    /// for the prefix steps are drawn from a compatible SequenceDb entry instead of
    /// the local seed pool.
    pub fn run_one(
        &mut self,
        seq_db: Option<&SequenceDb>,
    ) -> Result<(
        ExecStatus,
        usize,
        bool,
        Vec<ResourceWrite>,
        Vec<ExecResourceProfile>,
        Option<Vec<(Vec<VmTypeTag>, Vec<MoveValue>)>>,
    )> {
        // Use the same signer for all steps in the chain
        let sender = self.mutators[0].random_signer();
        let num_steps = self.chain.len();

        // Decide seed source: SequenceDb prefix (20%), local corpus, or generate
        let db_prefix_seed: Option<Vec<(Vec<VmTypeTag>, Vec<MoveValue>)>> = seq_db
            .filter(|db| db.prefix_compatible_count(&self.chain.steps) > 0)
            .filter(|_| self.mutators[0].random_percent() < SEQ_DB_PROB)
            .and_then(|db| db.pick_prefix_seed(&self.chain.steps, self.mutators[0].rng_mut()));

        // Generate or mutate inputs for ALL steps up front
        let step_inputs: Vec<(Vec<VmTypeTag>, Vec<MoveValue>)> = (0..num_steps)
            .map(|i| {
                // If we have a SequenceDb prefix seed that covers this step, use it
                // (with mutation applied)
                if let Some(ref prefix) = db_prefix_seed {
                    if i < prefix.len() {
                        let sig = &self.step_sigs[i];
                        let non_signer_params: Vec<_> = sig
                            .parameters
                            .iter()
                            .filter(|ty| !matches!(ty, BasicInput::Signer))
                            .collect();
                        let (seed_ty, seed_args) = &prefix[i];
                        let ty_args = if !sig.generics.is_empty()
                            && self.mutators[i].should_mutate_type_args()
                        {
                            self.mutators[i].mutate_type_args(&sig.generics, seed_ty)
                        } else {
                            seed_ty.clone()
                        };
                        let args = seed_args
                            .iter()
                            .zip(non_signer_params.iter())
                            .map(|(val, ty)| self.mutators[i].mutate_value(ty, val))
                            .collect();
                        return (ty_args, args);
                    }
                }

                let sig = &self.step_sigs[i];
                let non_signer_params: Vec<_> = sig
                    .parameters
                    .iter()
                    .filter(|ty| !matches!(ty, BasicInput::Signer))
                    .collect();

                match self.mutators[i].should_mutate(self.seedpool.len()) {
                    None => {
                        // Generate fresh inputs
                        let ty_args = self.mutators[i].random_type_args(&sig.generics);
                        let args = non_signer_params
                            .iter()
                            .map(|ty| self.mutators[i].random_value(ty))
                            .collect();
                        (ty_args, args)
                    },
                    Some(index) => {
                        // Mutate from corpus seed
                        let (seed_ty, seed_args) = &self.seedpool[index][i];
                        let ty_args = if !sig.generics.is_empty()
                            && self.mutators[i].should_mutate_type_args()
                        {
                            self.mutators[i].mutate_type_args(&sig.generics, seed_ty)
                        } else {
                            seed_ty.clone()
                        };
                        let args = seed_args
                            .iter()
                            .zip(non_signer_params.iter())
                            .map(|(val, ty)| self.mutators[i].mutate_value(ty, val))
                            .collect();
                        (ty_args, args)
                    },
                }
            })
            .collect();

        // Clear trace buffer ONCE at start of entire chain
        clear_tracing_buffer();

        // Execute chain steps sequentially, collecting per-step resource data
        let mut all_writes = vec![];
        let mut last_status = ExecStatus::Success;
        let mut step_raw_profiles: Vec<(usize, Vec<ResourceWrite>, Vec<ResourceRead>, bool)> =
            Vec::with_capacity(num_steps);

        for (step_idx, (ty_args, args)) in step_inputs.iter().enumerate() {
            let payload = TransactionPayload::Script(Script::new(
                self.step_codes[step_idx].clone(),
                ty_args.clone(),
                args.iter()
                    .map(|arg| {
                        TransactionArgument::Serialized(
                            MoveValue::simple_serialize(arg).expect("arguments must serialize"),
                        )
                    })
                    .collect(),
            ));

            let (vm_status, txn_status, writes, reads) =
                self.executor
                    .run_payload_with_sender_tracking(sender, payload)?;

            // Update object dictionaries in ALL mutators with writes from this step
            for mutator in self.mutators.iter_mut() {
                mutator.update_object_dict(&writes);
            }

            let step_status: ExecStatus = (vm_status, txn_status).into();
            let succeeded = matches!(step_status, ExecStatus::Success);

            // Collect raw profile data for this step (clone writes before moving)
            step_raw_profiles.push((
                self.chain.steps[step_idx],
                writes.clone(),
                reads,
                succeeded,
            ));

            if succeeded {
                all_writes.extend(writes);
            }

            // If a step fails, abort the chain early (predecessor setup failed)
            if !succeeded {
                last_status = step_status;
                self.exec_count += 1;
                // Flush and discard trace data
                flush_tracing_buffer();
                return Ok((
                    last_status,
                    self.seedpool.len(),
                    false,
                    all_writes,
                    vec![],
                    None,
                ));
            }
        }

        // All steps succeeded — flush trace buffer and read coverage from ALL steps
        flush_tracing_buffer();

        self.exec_count += 1;
        let coverage_map = CoverageMap::from_trace_file(&self.trace_path)?;
        let found_new = self.update_coverage(coverage_map);
        let (profiles, seed_clone) = if found_new {
            self.last_new_coverage_time = Some(Instant::now());
            let cloned = step_inputs.clone();
            self.seedpool.push(step_inputs);
            let profiles = step_raw_profiles
                .iter()
                .map(|(script_index, writes, reads, succeeded)| {
                    ExecResourceProfile::from_execution(*script_index, writes, reads, *succeeded)
                })
                .collect();
            (profiles, Some(cloned))
        } else {
            (vec![], None)
        };

        Ok((
            last_status,
            self.seedpool.len(),
            found_new,
            all_writes,
            profiles,
            seed_clone,
        ))
    }

    /// Absorb shared object discoveries from other fuzzers
    pub fn absorb_shared_object_writes(&mut self, writes: &[ResourceWrite]) {
        for mutator in self.mutators.iter_mut() {
            mutator.update_object_dict(writes);
        }
    }

    /// Import a seed from a parent sequence (for sequence extension).
    ///
    /// The `parent_seed` covers the first `parent_seed.len()` steps of this chain.
    /// Remaining steps get random inputs generated by their respective mutators.
    pub fn import_parent_seed(
        &mut self,
        mut parent_seed: Vec<(Vec<VmTypeTag>, Vec<MoveValue>)>,
    ) {
        let chain_len = self.chain.len();
        while parent_seed.len() < chain_len {
            let step_idx = parent_seed.len();
            let sig = &self.step_sigs[step_idx];
            let ty_args = self.mutators[step_idx].random_type_args(&sig.generics);
            let args: Vec<MoveValue> = sig
                .parameters
                .iter()
                .filter(|ty| !matches!(ty, BasicInput::Signer))
                .map(|ty| self.mutators[step_idx].random_value(ty))
                .collect();
            parent_seed.push((ty_args, args));
        }
        self.seedpool.push(parent_seed);
    }

    /// Update coverage map, return true if new coverage is found
    fn update_coverage(&mut self, new_map: CoverageMap) -> bool {
        let mut found_new = false;
        for new_exec_map in new_map.exec_maps.into_values() {
            for (key, new_module_map) in new_exec_map.module_maps {
                let module_map = self.coverage.module_maps.entry(key).or_insert_with(|| {
                    ModuleCoverageMap::new(new_module_map.module_addr, new_module_map.module_name)
                });
                for (ident, new_func_map) in new_module_map.function_maps {
                    let func_map = module_map.function_maps.entry(ident.clone()).or_default();
                    for (pos, count) in new_func_map {
                        if count == 0 {
                            continue;
                        }
                        if !func_map.contains_key(&pos) {
                            found_new = true;
                        }
                        let entry = func_map.entry(pos).or_insert(0);
                        *entry += count;
                    }
                }
            }
        }
        found_new
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use move_core_types::identifier::Identifier;
    use rand::SeedableRng;

    /// Helper: create a ResourceTag from a simple name
    fn make_tag(name: &str) -> ResourceTag {
        ResourceTag {
            struct_tag: StructTag {
                address: aptos_types::account_address::AccountAddress::ONE,
                module: Identifier::new("test").unwrap(),
                name: Identifier::new(name).unwrap(),
                type_args: vec![],
            },
        }
    }

    /// Helper: create a ScriptProfile
    fn make_profile(
        index: usize,
        reads: Vec<&str>,
        writes: Vec<&str>,
        succeeded: bool,
    ) -> ScriptProfile {
        ScriptProfile {
            script_index: index,
            reads: reads.into_iter().map(make_tag).collect(),
            writes: writes.into_iter().map(make_tag).collect(),
            ever_succeeded: succeeded,
        }
    }

    // -----------------------------------------------------------------------
    // DUG construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dug_from_profiles_basic() {
        // S0: writes {T_A}, reads {}
        // S1: writes {T_B}, reads {T_A}
        // S2: writes {}, reads {T_A, T_B}
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec!["A"], vec!["B"], true),
            make_profile(2, vec!["A", "B"], vec![], false),
        ];

        let dug = DefUseGraph::from_profiles(&profiles);

        assert_eq!(dug.num_scripts(), 3);
        assert_eq!(dug.num_types(), 2); // A, B

        // S0 defs A
        assert_eq!(dug.defs_of(0).len(), 1);
        // S1 defs B
        assert_eq!(dug.defs_of(1).len(), 1);
        // S2 never succeeded → no defs recorded
        assert_eq!(dug.defs_of(2).len(), 0);

        // S0 uses nothing
        assert!(dug.uses_of(0).is_empty());
        // S1 uses A
        assert_eq!(dug.uses_of(1).len(), 1);
        // S2 uses A, B
        assert_eq!(dug.uses_of(2).len(), 2);

        // Producers of A = {S0}, producers of B = {S1}
        let tag_a = make_tag("A");
        let tag_b = make_tag("B");
        let ti_a = *dug.type_index.get(&tag_a).unwrap();
        let ti_b = *dug.type_index.get(&tag_b).unwrap();
        assert_eq!(dug.producers_of(ti_a), &BTreeSet::from([0]));
        assert_eq!(dug.producers_of(ti_b), &BTreeSet::from([1]));

        // S2 has unmet deps = {A, B}
        assert_eq!(dug.unmet_deps(2).len(), 2);
        // S1 has unmet deps = {A}
        assert_eq!(dug.unmet_deps(1).len(), 1);
        // S0 has no unmet deps
        assert!(dug.unmet_deps(0).is_empty());

        // ever_succeeded
        assert!(dug.script_ever_succeeded(0));
        assert!(dug.script_ever_succeeded(1));
        assert!(!dug.script_ever_succeeded(2));
    }

    #[test]
    fn test_dug_empty() {
        let profiles: Vec<ScriptProfile> = vec![];
        let dug = DefUseGraph::from_profiles(&profiles);
        assert_eq!(dug.num_scripts(), 0);
        assert_eq!(dug.num_types(), 0);
    }

    #[test]
    fn test_dug_no_producers() {
        // S0: reads {T_X}, writes nothing, never succeeded
        let profiles = vec![make_profile(0, vec!["X"], vec![], false)];
        let dug = DefUseGraph::from_profiles(&profiles);

        assert_eq!(dug.num_types(), 1);
        let tag_x = make_tag("X");
        let ti_x = *dug.type_index.get(&tag_x).unwrap();
        assert!(dug.producers_of(ti_x).is_empty());
    }

    // -----------------------------------------------------------------------
    // Chain construction tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_chain_linear() {
        // S0: writes {A}, reads {}
        // S1: writes {B}, reads {A}
        // S2: writes {}, reads {B}   (never succeeded)
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec!["A"], vec!["B"], true),
            make_profile(2, vec!["B"], vec![], false),
        ];
        let dug = DefUseGraph::from_profiles(&profiles);
        let mut rng = StdRng::seed_from_u64(42);

        let chains = construct_chains(&dug, 5, 2, 10, &mut rng);

        // Should produce at least one chain ending at S2
        assert!(!chains.is_empty());
        let chain = &chains[0];
        assert_eq!(chain.target(), 2);
        // Chain must contain S1 (produces B) and may contain S0 (produces A for S1)
        assert!(chain.steps.contains(&1));
        // Target is last
        assert_eq!(*chain.steps.last().unwrap(), 2);
    }

    #[test]
    fn test_chain_diamond() {
        // S0: writes {A}, reads {}
        // S1: writes {B}, reads {}
        // S2: writes {}, reads {A, B}  (never succeeded)
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec![], vec!["B"], true),
            make_profile(2, vec!["A", "B"], vec![], false),
        ];
        let dug = DefUseGraph::from_profiles(&profiles);
        let mut rng = StdRng::seed_from_u64(42);

        let chains = construct_chains(&dug, 5, 2, 10, &mut rng);

        assert!(!chains.is_empty());
        let chain = &chains[0];
        assert_eq!(chain.target(), 2);
        // Chain must include both S0 and S1
        assert!(chain.steps.contains(&0));
        assert!(chain.steps.contains(&1));
        // Both must come before S2
        let pos_0 = chain.steps.iter().position(|&s| s == 0).unwrap();
        let pos_1 = chain.steps.iter().position(|&s| s == 1).unwrap();
        let pos_2 = chain.steps.iter().position(|&s| s == 2).unwrap();
        assert!(pos_0 < pos_2);
        assert!(pos_1 < pos_2);
    }

    #[test]
    fn test_chain_max_length() {
        // Deep chain: S0->A, S1 reads A writes B, S2 reads B writes C, S3 reads C writes D, S4 reads D
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec!["A"], vec!["B"], true),
            make_profile(2, vec!["B"], vec!["C"], true),
            make_profile(3, vec!["C"], vec!["D"], true),
            make_profile(4, vec!["D"], vec![], false),
        ];
        let dug = DefUseGraph::from_profiles(&profiles);
        let mut rng = StdRng::seed_from_u64(42);

        // max_chain_length = 3 → chain can have at most 3 steps
        let chains = construct_chains(&dug, 3, 2, 10, &mut rng);

        assert!(!chains.is_empty());
        let chain = &chains[0];
        assert!(chain.len() <= 3);
        assert_eq!(chain.target(), 4);
    }

    #[test]
    fn test_chain_self_sufficient() {
        // S0: reads {A}, writes {A}  (self-sufficient: reads what it writes)
        let profiles = vec![make_profile(0, vec!["A"], vec!["A"], true)];
        let dug = DefUseGraph::from_profiles(&profiles);
        let mut rng = StdRng::seed_from_u64(42);

        let chains = construct_chains(&dug, 5, 2, 10, &mut rng);

        // No chain needed — unmet_deps is empty
        assert!(chains.is_empty());
    }

    #[test]
    fn test_chain_no_producer() {
        // S0: reads {X}, writes {} (never succeeded, X has no producer)
        let profiles = vec![make_profile(0, vec!["X"], vec![], false)];
        let dug = DefUseGraph::from_profiles(&profiles);
        let mut rng = StdRng::seed_from_u64(42);

        let chains = construct_chains(&dug, 5, 2, 10, &mut rng);

        // S0 has unmet deps but no producer can be found → no chain
        assert!(chains.is_empty());
    }

    #[test]
    fn test_chain_repetition_limit() {
        // S0: reads {A}, writes {A, B}  (succeeded, needs itself for A)
        // S1: reads {B}, writes {}  (never succeeded)
        // S0 is both the producer and consumer of A. With max_repetition=1,
        // it can only appear once, so the self-dependency on A won't add a duplicate.
        let profiles = vec![
            make_profile(0, vec!["A"], vec!["A", "B"], true),
            make_profile(1, vec!["B"], vec![], false),
        ];
        let dug = DefUseGraph::from_profiles(&profiles);
        let mut rng = StdRng::seed_from_u64(42);

        let chains = construct_chains(&dug, 5, 1, 10, &mut rng);

        // Should produce chain [S0, S1]
        assert!(!chains.is_empty());
        let chain = &chains[0];
        assert_eq!(chain.target(), 1);
        // S0 appears exactly once
        assert_eq!(chain.steps.iter().filter(|&&s| s == 0).count(), 1);
    }

    #[test]
    fn test_chain_multiple_producers() {
        // S0 and S1 both produce A; S2 reads A (never succeeded)
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec![], vec!["A"], true),
            make_profile(2, vec!["A"], vec![], false),
        ];
        let dug = DefUseGraph::from_profiles(&profiles);
        let mut rng = StdRng::seed_from_u64(42);

        let chains = construct_chains(&dug, 5, 2, 10, &mut rng);

        assert!(!chains.is_empty());
        let chain = &chains[0];
        assert_eq!(chain.target(), 2);
        // Chain should have one of S0 or S1 as producer (either is fine)
        assert!(chain.steps.contains(&0) || chain.steps.contains(&1));
        assert_eq!(chain.len(), 2);
    }

    // -----------------------------------------------------------------------
    // DUG mutation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dug_add_def_basic() {
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec!["A"], vec![], false),
        ];
        let mut dug = DefUseGraph::from_profiles(&profiles);
        assert_eq!(dug.num_types(), 1); // only A

        // Add a new def: S1 writes B (new type)
        let tag_b = make_tag("B");
        let changed = dug.add_def(1, &tag_b);
        assert!(changed);
        assert_eq!(dug.num_types(), 2); // A and B
        assert_eq!(dug.defs_of(1).len(), 1);
        let ti_b = *dug.type_index.get(&tag_b).unwrap();
        assert!(dug.producers_of(ti_b).contains(&1));
    }

    #[test]
    fn test_dug_add_def_idempotent() {
        let profiles = vec![make_profile(0, vec![], vec!["A"], true)];
        let mut dug = DefUseGraph::from_profiles(&profiles);
        let marker = dug.modification_marker();

        // Adding the same def again should not change the DUG
        let tag_a = make_tag("A");
        let changed = dug.add_def(0, &tag_a);
        assert!(!changed);
        assert!(!dug.has_changed_since(marker));
    }

    #[test]
    fn test_dug_add_use_basic() {
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec![], vec![], true),
        ];
        let mut dug = DefUseGraph::from_profiles(&profiles);
        assert!(dug.uses_of(1).is_empty());

        // S1 now reads A
        let tag_a = make_tag("A");
        let changed = dug.add_use(1, &tag_a);
        assert!(changed);
        assert_eq!(dug.uses_of(1).len(), 1);
    }

    #[test]
    fn test_dug_add_use_new_type() {
        let profiles = vec![make_profile(0, vec![], vec![], false)];
        let mut dug = DefUseGraph::from_profiles(&profiles);
        assert_eq!(dug.num_types(), 0);

        // S0 reads X (type X does not exist yet)
        let tag_x = make_tag("X");
        let changed = dug.add_use(0, &tag_x);
        assert!(changed);
        assert_eq!(dug.num_types(), 1);
        assert_eq!(dug.uses_of(0).len(), 1);
    }

    #[test]
    fn test_dug_mark_succeeded() {
        let profiles = vec![make_profile(0, vec!["A"], vec![], false)];
        let mut dug = DefUseGraph::from_profiles(&profiles);
        assert!(!dug.script_ever_succeeded(0));

        let changed = dug.mark_succeeded(0);
        assert!(changed);
        assert!(dug.script_ever_succeeded(0));

        // Idempotent
        let changed2 = dug.mark_succeeded(0);
        assert!(!changed2);
    }

    #[test]
    fn test_dug_modification_tracking() {
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec!["A"], vec![], false),
        ];
        let mut dug = DefUseGraph::from_profiles(&profiles);
        let m0 = dug.modification_marker();

        // No change yet
        assert!(!dug.has_changed_since(m0));

        // Add a new def
        dug.add_def(1, &make_tag("B"));
        assert!(dug.has_changed_since(m0));
        let m1 = dug.modification_marker();
        assert!(!dug.has_changed_since(m1));
    }

    #[test]
    fn test_dug_ingest_profile() {
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec![], vec![], false),
        ];
        let mut dug = DefUseGraph::from_profiles(&profiles);
        let m0 = dug.modification_marker();

        // Ingest a profile where S1 reads A and writes B, and succeeded
        let profile = ExecResourceProfile {
            script_index: 1,
            reads: vec![make_tag("A")].into_iter().collect(),
            writes: vec![make_tag("B")].into_iter().collect(),
            succeeded: true,
        };
        dug.ingest_profile(&profile);

        assert!(dug.has_changed_since(m0));
        assert!(dug.script_ever_succeeded(1));
        assert_eq!(dug.uses_of(1).len(), 1); // reads A
        assert_eq!(dug.defs_of(1).len(), 1); // writes B
        assert_eq!(dug.num_types(), 2); // A and B
    }

    #[test]
    fn test_dug_chain_reconstruction_after_mutation() {
        // Initially: S0 writes A, S1 reads nothing (no chain possible to S1)
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec![], vec![], false),
        ];
        let mut dug = DefUseGraph::from_profiles(&profiles);
        let mut rng = StdRng::seed_from_u64(42);

        let chains_before = construct_chains(&dug, 5, 2, 10, &mut rng);
        // S1 has no unmet deps, so no chains to it
        assert!(chains_before.iter().all(|c| c.target() != 1));

        // Now S1 reads A — this creates an unmet dependency that S0 can resolve
        dug.add_use(1, &make_tag("A"));

        let mut rng2 = StdRng::seed_from_u64(42);
        let chains_after = construct_chains(&dug, 5, 2, 10, &mut rng2);
        // Now there should be a chain [S0, S1]
        let chain_to_1 = chains_after.iter().find(|c| c.target() == 1);
        assert!(chain_to_1.is_some());
        let chain = chain_to_1.unwrap();
        assert!(chain.steps.contains(&0));
    }

    // -----------------------------------------------------------------------
    // DUG accessor tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_dug_type_index_of() {
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec!["A"], vec!["B"], true),
        ];
        let dug = DefUseGraph::from_profiles(&profiles);

        // Known tags should return Some
        assert!(dug.type_index_of(&make_tag("A")).is_some());
        assert!(dug.type_index_of(&make_tag("B")).is_some());
        // Indices should be distinct
        assert_ne!(
            dug.type_index_of(&make_tag("A")),
            dug.type_index_of(&make_tag("B"))
        );
        // Unknown tag should return None
        assert!(dug.type_index_of(&make_tag("C")).is_none());
    }

    #[test]
    fn test_dug_consumers_of() {
        // S0 writes A, S1 and S2 read A
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec!["A"], vec![], false),
            make_profile(2, vec!["A"], vec![], false),
        ];
        let dug = DefUseGraph::from_profiles(&profiles);

        let ti_a = *dug.type_index_of(&make_tag("A")).unwrap();
        let consumers = dug.consumers_of(ti_a);
        assert_eq!(consumers, BTreeSet::from([1, 2]));

        // S0 doesn't read A, so it's not a consumer
        assert!(!consumers.contains(&0));
    }

    // -----------------------------------------------------------------------
    // SequenceDb tests
    // -----------------------------------------------------------------------

    /// Helper: create an ExecResourceProfile for testing
    fn make_exec_profile(
        script_index: usize,
        reads: Vec<&str>,
        writes: Vec<&str>,
        succeeded: bool,
    ) -> ExecResourceProfile {
        ExecResourceProfile {
            script_index,
            reads: reads.into_iter().map(make_tag).collect(),
            writes: writes.into_iter().map(make_tag).collect(),
            succeeded,
        }
    }

    #[test]
    fn test_seq_db_add_and_retrieve() {
        let mut db = SequenceDb::new();
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);

        let profiles = vec![
            make_exec_profile(0, vec![], vec!["A"], true),
            make_exec_profile(1, vec!["A"], vec!["B"], true),
        ];
        let seed = vec![
            (vec![], vec![MoveValue::U64(42)]),
            (vec![], vec![MoveValue::Bool(true)]),
        ];

        let id = db.add_entry(vec![0, 1], seed.clone(), &profiles);
        assert_eq!(id, 0);
        assert_eq!(db.len(), 1);
        assert!(!db.is_empty());

        // Verify the entry
        let entries = db.find_prefix_seeds(&[0, 1]);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].steps, vec![0, 1]);
        assert!(entries[0].all_succeeded);
        assert!(entries[0].produced_types.contains(&make_tag("A")));
        assert!(entries[0].produced_types.contains(&make_tag("B")));
        assert!(entries[0].consumed_types.contains(&make_tag("A")));
    }

    #[test]
    fn test_seq_db_prefix_matching_exact() {
        let mut db = SequenceDb::new();
        let profiles = vec![
            make_exec_profile(0, vec![], vec!["A"], true),
            make_exec_profile(1, vec!["A"], vec!["B"], true),
            make_exec_profile(2, vec!["B"], vec![], true),
        ];
        let seed = vec![
            (vec![], vec![MoveValue::U64(1)]),
            (vec![], vec![MoveValue::U64(2)]),
            (vec![], vec![MoveValue::U64(3)]),
        ];
        db.add_entry(vec![0, 1, 2], seed, &profiles);

        // Exact match
        let matches = db.find_prefix_seeds(&[0, 1, 2]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].steps, vec![0, 1, 2]);
    }

    #[test]
    fn test_seq_db_prefix_matching_superchain() {
        let mut db = SequenceDb::new();
        let profiles = vec![
            make_exec_profile(0, vec![], vec!["A"], true),
            make_exec_profile(1, vec!["A"], vec![], true),
        ];
        let seed = vec![
            (vec![], vec![MoveValue::U64(1)]),
            (vec![], vec![MoveValue::U64(2)]),
        ];
        db.add_entry(vec![0, 1], seed, &profiles);

        // Entry [0,1] is a prefix of chain [0,1,2]
        let matches = db.find_prefix_seeds(&[0, 1, 2]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].steps, vec![0, 1]);
    }

    #[test]
    fn test_seq_db_prefix_no_match() {
        let mut db = SequenceDb::new();
        let profiles = vec![
            make_exec_profile(0, vec![], vec!["A"], true),
            make_exec_profile(1, vec![], vec![], true),
            make_exec_profile(3, vec![], vec![], true),
        ];
        let seed = vec![
            (vec![], vec![MoveValue::U64(1)]),
            (vec![], vec![MoveValue::U64(2)]),
            (vec![], vec![MoveValue::U64(3)]),
        ];
        db.add_entry(vec![0, 1, 3], seed, &profiles);

        // [0,1,3] is not a prefix of [0,1,2] (step 2 at position 2 differs from step 3)
        let matches = db.find_prefix_seeds(&[0, 1, 2]);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_seq_db_prefix_longer_entry() {
        let mut db = SequenceDb::new();
        let profiles = vec![
            make_exec_profile(0, vec![], vec!["A"], true),
            make_exec_profile(1, vec![], vec![], true),
            make_exec_profile(2, vec![], vec![], true),
            make_exec_profile(3, vec![], vec![], true),
        ];
        let seed = vec![
            (vec![], vec![MoveValue::U64(1)]),
            (vec![], vec![MoveValue::U64(2)]),
            (vec![], vec![MoveValue::U64(3)]),
            (vec![], vec![MoveValue::U64(4)]),
        ];
        db.add_entry(vec![0, 1, 2, 3], seed, &profiles);

        // Entry [0,1,2,3] is longer than chain [0,1], not a prefix
        let matches = db.find_prefix_seeds(&[0, 1]);
        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_seq_db_propose_extensions() {
        // DUG: S0 writes A, S1 reads A and writes B, S2 reads B
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec!["A"], vec!["B"], true),
            make_profile(2, vec!["B"], vec![], false),
        ];
        let dug = DefUseGraph::from_profiles(&profiles);

        let mut db = SequenceDb::new();
        // Stored sequence [0, 1] that produced type B
        let exec_profiles = vec![
            make_exec_profile(0, vec![], vec!["A"], true),
            make_exec_profile(1, vec!["A"], vec!["B"], true),
        ];
        let seed = vec![
            (vec![], vec![MoveValue::U64(1)]),
            (vec![], vec![MoveValue::U64(2)]),
        ];
        db.add_entry(vec![0, 1], seed, &exec_profiles);

        // Should propose [0, 1, 2] because S2 reads B which is produced by the sequence
        let extensions = db.propose_extensions(&dug, 5, 10);
        assert!(!extensions.is_empty());
        let ext_chain = &extensions[0].0;
        assert_eq!(ext_chain.steps, vec![0, 1, 2]);
        // Parent seed should have 2 entries (for the prefix)
        assert_eq!(extensions[0].1.len(), 2);
    }

    #[test]
    fn test_seq_db_no_extension_for_failing_sequence() {
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec!["A"], vec!["B"], true),
            make_profile(2, vec!["B"], vec![], false),
        ];
        let dug = DefUseGraph::from_profiles(&profiles);

        let mut db = SequenceDb::new();
        // Entry where one step failed
        let exec_profiles = vec![
            make_exec_profile(0, vec![], vec!["A"], true),
            make_exec_profile(1, vec!["A"], vec!["B"], false), // failed!
        ];
        let seed = vec![
            (vec![], vec![MoveValue::U64(1)]),
            (vec![], vec![MoveValue::U64(2)]),
        ];
        db.add_entry(vec![0, 1], seed, &exec_profiles);

        // Should not propose extensions for failing sequences
        let extensions = db.propose_extensions(&dug, 5, 10);
        assert!(extensions.is_empty());
    }

    #[test]
    fn test_seq_db_no_extension_at_max_length() {
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec!["A"], vec!["B"], true),
            make_profile(2, vec!["B"], vec![], false),
        ];
        let dug = DefUseGraph::from_profiles(&profiles);

        let mut db = SequenceDb::new();
        let exec_profiles = vec![
            make_exec_profile(0, vec![], vec!["A"], true),
            make_exec_profile(1, vec!["A"], vec!["B"], true),
        ];
        let seed = vec![
            (vec![], vec![MoveValue::U64(1)]),
            (vec![], vec![MoveValue::U64(2)]),
        ];
        db.add_entry(vec![0, 1], seed, &exec_profiles);

        // Max chain length is 2, entry has 2 steps → no extension possible
        let extensions = db.propose_extensions(&dug, 2, 10);
        assert!(extensions.is_empty());
    }

    #[test]
    fn test_seq_db_no_extension_already_in_chain() {
        // DUG: S0 writes A, S1 reads A and writes B, S1 also reads B (self-loop)
        let profiles = vec![
            make_profile(0, vec![], vec!["A"], true),
            make_profile(1, vec!["A", "B"], vec!["B"], true),
        ];
        let dug = DefUseGraph::from_profiles(&profiles);

        let mut db = SequenceDb::new();
        let exec_profiles = vec![
            make_exec_profile(0, vec![], vec!["A"], true),
            make_exec_profile(1, vec!["A", "B"], vec!["B"], true),
        ];
        let seed = vec![
            (vec![], vec![MoveValue::U64(1)]),
            (vec![], vec![MoveValue::U64(2)]),
        ];
        db.add_entry(vec![0, 1], seed, &exec_profiles);

        // S1 reads B (which is produced by the sequence), but S1 is already in the chain
        // S0 also reads nothing of B. The only consumer of B is S1, which is in-chain.
        let extensions = db.propose_extensions(&dug, 5, 10);
        // S0 also reads A but is already in chain.
        // Both consumers of produced types are already in the chain.
        assert!(extensions.is_empty());
    }
}
