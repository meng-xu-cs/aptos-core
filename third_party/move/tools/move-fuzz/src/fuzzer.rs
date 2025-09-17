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
    type_recursion_depth: usize,
) -> Result<()> {
    // build a model on the packages
    let mut model = Model::new();
    model.provision(&pkg_defs, type_recursion_depth);

    todo!()
}
