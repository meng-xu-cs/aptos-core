// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    common::Account,
    deps::{PkgDefinition, PkgManifest},
    language::LanguageSetting,
    prep::model::Model,
};
use anyhow::Result;
use std::collections::BTreeMap;

/// Entrypoint for the fuzzer
pub fn entrypoint(
    pkg_defs: Vec<PkgDefinition>,
    named_accounts: BTreeMap<String, Account>,
    language: LanguageSetting,
    autogen_manifest: PkgManifest,
    seed: Option<u64>,
    max_trace_depth: usize,
    max_call_repetition: usize,
) -> Result<()> {
    // build a model on the packages
    let model = Model::new(&pkg_defs, max_trace_depth, max_call_repetition);
    model.populate();

    todo!()
}
