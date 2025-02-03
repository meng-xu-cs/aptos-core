use crate::{
    common::PkgDefinition,
    fuzz::{canvas::BasicType, ident::FunctionIdent},
};
use move_binary_format::{
    access::{ModuleAccess, ScriptAccess},
    binary_views::BinaryIndexedView,
    file_format::{Signature, SignatureToken},
};
use move_compiler::compiled_unit::CompiledUnit;
use move_core_types::account_address::AccountAddress;
use move_package::compilation::compiled_package::CompiledUnitWithSource;
use std::collections::BTreeMap;

/// An identifier to an entrypoint to the contracts
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum EntrypointIdent {
    Function(FunctionIdent),
    Script(String),
}

/// The definition of an entrypoint to the contracts
#[derive(Debug)]
pub struct EntrypointDetails {
    params: Vec<BasicType>,
}

/// A database of entrypoints
pub struct Preparer {
    entrypoints: BTreeMap<EntrypointIdent, EntrypointDetails>,
}

impl Preparer {
    pub fn new(pkgs: &[PkgDefinition]) -> Self {
        // populate the entrypoint registry
        let mut entrypoints = BTreeMap::new();
        for pkg in pkgs {
            let is_primary = matches!(pkg, PkgDefinition::Primary(_));

            // TODO: handle non-primary modules or scripts
            if !is_primary {
                continue;
            }

            for CompiledUnitWithSource {
                unit,
                source_path: _,
            } in &pkg.as_built_package().package.root_compiled_units
            {
                match unit {
                    CompiledUnit::Script(script) => {
                        // NOTE: simplified assumption that every script has a different name
                        let ident = EntrypointIdent::Script(script.name.to_string());
                        let script = &script.script;

                        // NOTE: assuming no generic types for simplification
                        // TODO: remove this simplification
                        assert!(script.type_parameters.is_empty());
                        let params = Self::convert_entry_parameters(
                            &BinaryIndexedView::Script(script),
                            script.signature_at(script.parameters),
                        );

                        // register to mapping
                        let existing = entrypoints.insert(ident, EntrypointDetails { params });
                        assert!(existing.is_none());
                    },
                    CompiledUnit::Module(module) => {
                        // go over all functions defined
                        let module = &module.module;
                        for def in &module.function_defs {
                            // we only care about entry functions
                            if !def.is_entry {
                                continue;
                            }

                            let handle = module.function_handle_at(def.function);
                            let ident = EntrypointIdent::Function(
                                FunctionIdent::from_function_handle(module, handle),
                            );

                            log::debug!(
                                "processing {}",
                                FunctionIdent::from_function_handle(module, handle)
                            );

                            // NOTE: assuming no generic types for simplification
                            // TODO: remove this simplification
                            assert!(handle.type_parameters.is_empty());
                            let params = Self::convert_entry_parameters(
                                &BinaryIndexedView::Module(module),
                                module.signature_at(handle.parameters),
                            );

                            // register to mapping
                            let existing = entrypoints.insert(ident, EntrypointDetails { params });
                            assert!(existing.is_none());
                        }
                    },
                };
            }
        }

        Self { entrypoints }
    }

    fn convert_entry_parameters(binary: &BinaryIndexedView, params: &Signature) -> Vec<BasicType> {
        params
            .0
            .iter()
            .map(|token| Self::convert_entry_signature_token(binary, token))
            .collect()
    }

    /// Convert a signature token
    fn convert_entry_signature_token(
        binary: &BinaryIndexedView,
        token: &SignatureToken,
    ) -> BasicType {
        match token {
            SignatureToken::Bool => return BasicType::Bool,
            SignatureToken::U8 => return BasicType::U8,
            SignatureToken::U16 => return BasicType::U16,
            SignatureToken::U32 => return BasicType::U32,
            SignatureToken::U64 => return BasicType::U64,
            SignatureToken::U128 => return BasicType::U128,
            SignatureToken::U256 => return BasicType::U256,
            SignatureToken::Address => return BasicType::Address,
            SignatureToken::Signer => return BasicType::Signer,
            SignatureToken::Vector(inner) => {
                return BasicType::Vector(
                    Self::convert_entry_signature_token(binary, inner).into(),
                );
            },
            SignatureToken::Reference(inner) => {
                if matches!(inner.as_ref(), SignatureToken::Signer) {
                    return BasicType::Signer;
                }
            },
            SignatureToken::Struct(index) => {
                let struct_handle = binary.struct_handle_at(*index);
                if binary.identifier_at(struct_handle.name).as_str() == "String" {
                    let module_handle = binary.module_handle_at(struct_handle.module);
                    if *binary.address_identifier_at(module_handle.address) == AccountAddress::ONE
                        && binary.identifier_at(module_handle.name).as_str() == "string"
                    {
                        return BasicType::String;
                    }
                }
            },
            _ => (),
        };
        panic!(
            "unexpected signature token as entrypoint arguments: {:?}",
            token
        )
    }
}
