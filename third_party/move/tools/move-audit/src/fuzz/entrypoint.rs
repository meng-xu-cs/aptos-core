use crate::fuzz::{
    ident::FunctionIdent,
    typing::{DatatypeRegistry, TypeRef},
};
use move_binary_format::{
    access::ModuleAccess,
    file_format::{AbilitySet, Visibility},
    CompiledModule,
};
use std::collections::BTreeMap;

/// Declaration of a function
pub struct FunctionDecl {
    ident: FunctionIdent,
    generics: Vec<AbilitySet>,
    parameters: Vec<TypeRef>,
    return_val: Vec<TypeRef>,
    is_primary: bool,
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
            let return_val = module
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
                return_val,
                is_primary,
            };
            let existing = self.decls.insert(ident, decl);
            assert!(existing.is_none());
        }
    }
}
