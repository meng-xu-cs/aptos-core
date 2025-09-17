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
use std::collections::BTreeMap;

/// Declaration of a function
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct FunctionDecl {
    pub ident: FunctionIdent,
    pub generics: Vec<AbilitySet>,
    pub parameters: Vec<TypeRef>,
    pub return_sig: Vec<TypeRef>,
    pub kind: PkgKind,
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

    /// Analyze a module and register public functions found in this module
    pub fn analyze(&mut self, typing: &DatatypeRegistry, module: &CompiledModule, kind: PkgKind) {
        let binary = BinaryIndexedView::Module(module);

        // go over all functions defined
        for def in &module.function_defs {
            // we only care about public functions
            if !matches!(def.visibility, Visibility::Public) {
                continue;
            }

            let handle = binary.function_handle_at(def.function);
            let ident = FunctionIdent::from_function_handle(&binary, handle);

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
