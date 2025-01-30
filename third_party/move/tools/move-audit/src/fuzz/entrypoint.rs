use crate::fuzz::{
    ident::FunctionIdent,
    typing::{DatatypeRegistry, TypeRef},
};
use move_binary_format::{access::ModuleAccess, file_format::Visibility, CompiledModule};
use move_core_types::ability::AbilitySet;
use std::collections::BTreeMap;

/// Declaration of a function
pub struct FunctionDecl {
    pub ident: FunctionIdent,
    pub generics: Vec<AbilitySet>,
    pub parameters: Vec<TypeRef>,
    pub return_sig: Vec<TypeRef>,
    pub is_primary: bool,
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
    pub fn analyze(
        &mut self,
        typing: &DatatypeRegistry,
        module: &CompiledModule,
        is_primary: bool,
    ) {
        // go over all functions defined
        for def in &module.function_defs {
            // we only care about public functions
            if !matches!(def.visibility, Visibility::Public) {
                continue;
            }

            let handle = module.function_handle_at(def.function);
            let ident = FunctionIdent::from_function_handle(module, handle);

            // parse parameters and return types
            let parameters = module
                .signature_at(handle.parameters)
                .0
                .iter()
                .map(|token| typing.convert_signature_token(module, token))
                .collect();
            let return_sig = module
                .signature_at(handle.return_)
                .0
                .iter()
                .map(|token| typing.convert_signature_token(module, token))
                .collect();

            // add the declaration
            let decl = FunctionDecl {
                ident: ident.clone(),
                generics: handle.type_parameters.clone(),
                parameters,
                return_sig,
                is_primary,
            };
            let existing = self.decls.insert(ident, decl);
            assert!(existing.is_none());
        }
    }

    /// Return an iterator for all declarations collected
    pub fn iter_decls(&self) -> impl Iterator<Item = &FunctionDecl> {
        self.decls.values()
    }
}
