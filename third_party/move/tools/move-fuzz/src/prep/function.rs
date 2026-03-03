// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    deps::PkgKind,
    prep::{datatype::DatatypeRegistry, ident::FunctionIdent, typing::TypeRef},
};
use move_binary_format::{
    binary_views::BinaryIndexedView, file_format::Visibility, CompiledModule,
};
use move_core_types::ability::AbilitySet;
use std::collections::{BTreeMap, BTreeSet};

/// Declaration of a function
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct FunctionDecl {
    pub ident: FunctionIdent,
    pub generics: Vec<AbilitySet>,
    pub parameters: Vec<TypeRef>,
    pub return_sig: Vec<TypeRef>,
    pub kind: PkgKind,
    pub is_entry: bool,
}

pub struct FunctionRegistry {
    decls: BTreeMap<FunctionIdent, FunctionDecl>,
}

impl FunctionRegistry {
    /// Create an empty registry
    pub fn new() -> Self {
        Self {
            decls: BTreeMap::new(),
        }
    }

    /// Analyze a module and register script-callable functions found in this module.
    ///
    /// We register only externally callable functions (`public` visibility).
    /// `entry` metadata is retained for prioritization.
    pub fn analyze(
        &mut self,
        typing: &DatatypeRegistry,
        module: &CompiledModule,
        kind: PkgKind,
        source_text: Option<&str>,
    ) {
        let binary = BinaryIndexedView::Module(module);
        let script_public_funs = source_text.map(parse_script_public_functions);

        // go over all functions defined
        for def in &module.function_defs {
            if !matches!(def.visibility, Visibility::Public) {
                continue;
            }

            let handle = binary.function_handle_at(def.function);
            let ident = FunctionIdent::from_function_handle(&binary, handle);
            if let Some(public_funs) = &script_public_funs {
                if !public_funs.contains(ident.function_name()) {
                    continue;
                }
            }

            // parse parameters and return types
            let parameters = binary
                .signature_at(handle.parameters)
                .0
                .iter()
                .map(|token| typing.convert_signature_token(&binary, token))
                .collect();
            let return_sig = binary
                .signature_at(handle.return_)
                .0
                .iter()
                .map(|token| typing.convert_signature_token(&binary, token))
                .collect();

            // add the declaration
            let decl = FunctionDecl {
                ident: ident.clone(),
                generics: handle.type_parameters.clone(),
                parameters,
                return_sig,
                kind,
                is_entry: def.is_entry,
            };
            let existing = self.decls.insert(ident, decl);
            assert!(existing.is_none());
        }
    }

    /// Lookup a function declaration
    pub fn lookup_decl(&self, ident: &FunctionIdent) -> &FunctionDecl {
        self.decls
            .get(ident)
            .unwrap_or_else(|| panic!("unregistered function {ident}"))
    }

    /// Return an iterator for all declarations collected
    pub fn iter_decls(&self) -> impl Iterator<Item = &FunctionDecl> {
        self.decls.values()
    }
}

fn parse_script_public_functions(source: &str) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for line in source.lines() {
        let mut s = line.trim_start();
        if !s.starts_with("public") {
            continue;
        }
        // `public(package)` and `public(friend)` are not callable from scripts.
        if s.starts_with("public(") {
            continue;
        }

        s = s["public".len()..].trim_start();
        if s.starts_with("entry") {
            s = s["entry".len()..].trim_start();
        }
        if let Some(rest) = s.strip_prefix("fun ") {
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                result.insert(name);
            }
        }
    }
    result
}
