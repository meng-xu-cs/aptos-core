use crate::{
    common::PkgDefinition,
    fuzz::{
        ident::{DatatypeIdent, FunctionIdent},
        typing::{DatatypeContent, DatatypeRegistry, TypeBase, TypeRef, VectorVariant},
    },
};
use move_binary_format::{
    access::{ModuleAccess, ScriptAccess},
    binary_views::BinaryIndexedView,
    file_format::{Signature, Visibility},
};
use move_compiler::compiled_unit::CompiledUnit;
use move_core_types::value::MoveTypeLayout;
use move_package::compilation::compiled_package::CompiledUnitWithSource;
use std::{collections::BTreeMap, fmt::Display};

/// An identifier to an entrypoint to the contracts
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum EntrypointIdent {
    EntryFunction(FunctionIdent),
    PublicFunction(FunctionIdent),
    Script(String),
}

impl Display for EntrypointIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Script(ident) => ident.fmt(f),
            Self::EntryFunction(ident) | Self::PublicFunction(ident) => ident.fmt(f),
        }
    }
}

/// The definition of an entrypoint to the contracts
#[derive(Debug)]
pub struct EntrypointDetails {
    params: Vec<RuntimeType>,
}

/// Type that can appear on an entrypoint parameter
#[derive(Debug)]
pub enum RuntimeType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Bitvec,
    String,
    Address,
    Signer,
    Option(Box<Self>),
    Vector(Box<Self>),
    Object(DatatypeIdent, Vec<TypeBase>),
    Datatype(Vec<Vec<Self>>),
}

/// Captures all pre-fuzzing preparation
pub struct Preparer {
    /// a database of entry-points
    entrypoints: BTreeMap<EntrypointIdent, EntrypointDetails>,
}

impl Preparer {
    pub fn new(pkgs: &[PkgDefinition]) -> Self {
        // initialize the datatype registry
        let mut datatype_registry = DatatypeRegistry::new();
        for pkg in pkgs {
            let is_primary = matches!(pkg, PkgDefinition::Primary(_));
            for CompiledUnitWithSource {
                unit,
                source_path: _,
            } in &pkg.as_built_package().package.root_compiled_units
            {
                let module = match unit {
                    CompiledUnit::Script(_) => continue,
                    CompiledUnit::Module(m) => &m.module,
                };

                // go over all datatypes defined
                datatype_registry.analyze(module, is_primary);
            }
        }

        // initialize the entrypoint registry
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
                        let binary = BinaryIndexedView::Script(script);

                        // NOTE: assuming no generic types for simplification
                        // TODO: remove this simplification
                        assert!(script.type_parameters.is_empty());

                        let mut params = vec![];
                        for (ty_base, ty_runtime) in Self::convert_signature(
                            &datatype_registry,
                            &binary,
                            script.signature_at(script.parameters),
                        ) {
                            // sanity check
                            assert!(
                                matches!(ty_base, TypeBase::Signer)
                                    || ty_base.abilities().has_copy()
                            );
                            params.push(ty_runtime);
                        }

                        // register to mapping
                        let existing = entrypoints.insert(ident, EntrypointDetails { params });
                        assert!(existing.is_none());
                    },
                    CompiledUnit::Module(module) => {
                        // go over all functions defined
                        let module = &module.module;
                        let binary = BinaryIndexedView::Module(module);
                        for def in &module.function_defs {
                            // we only care about public functions
                            if !matches!(def.visibility, Visibility::Public) {
                                continue;
                            }

                            let handle = binary.function_handle_at(def.function);
                            let ident = FunctionIdent::from_function_handle(&binary, handle);

                            // NOTE: assuming no generic types for simplification
                            // TODO: remove this simplification
                            if !handle.type_parameters.is_empty() {
                                log::warn!("skipping entrypoint {ident} due to type generics");
                                continue;
                            }

                            // check parameters
                            let mut should_skip = false;
                            let mut params = vec![];
                            for (ty_base, ty_runtime) in Self::convert_signature(
                                &datatype_registry,
                                &binary,
                                module.signature_at(handle.parameters),
                            ) {
                                if !ty_base.abilities().has_copy()
                                    && !matches!(ty_base, TypeBase::Signer)
                                {
                                    assert!(!def.is_entry);
                                    // NOTE: skip functions that take non-trivial arguments
                                    // TODO: remove this simplification
                                    should_skip = true;
                                    break;
                                }
                                params.push(ty_runtime);
                            }

                            if should_skip {
                                log::warn!(
                                    "skipping entrypoint {ident} due to non-trivial arguments"
                                );
                                continue;
                            }

                            // sanity check on entry functions
                            let ret_ty = binary.signature_at(handle.return_);
                            if def.is_entry {
                                assert!(ret_ty.0.is_empty());
                            } else {
                                for token in ret_ty.0.iter() {
                                    let ty_ref =
                                        datatype_registry.convert_signature_token(&binary, token);

                                    // TODO: assumed no type arguments above for simplicity
                                    let ty_base =
                                        datatype_registry.instantiate_type_ref(&ty_ref, &[]);
                                    if !ty_base.abilities().has_drop() {
                                        should_skip = true;
                                        break;
                                    }
                                }
                            }
                            if should_skip {
                                log::warn!(
                                    "skipping entrypoint {ident} due to non-trivial return value"
                                );
                                continue;
                            }

                            // register to mapping
                            let ident = if def.is_entry {
                                EntrypointIdent::EntryFunction(ident)
                            } else {
                                EntrypointIdent::PublicFunction(ident)
                            };
                            let existing = entrypoints.insert(ident, EntrypointDetails { params });
                            assert!(existing.is_none());
                        }
                    },
                };
            }
        }

        log::info!("entrypoints discovered: {}", entrypoints.len());
        Self { entrypoints }
    }

    fn convert_signature(
        registry: &DatatypeRegistry,
        binary: &BinaryIndexedView,
        params: &Signature,
    ) -> Vec<(TypeBase, RuntimeType)> {
        let mut param_types = vec![];
        for token in params.0.iter() {
            let ty_tag = match registry.convert_signature_token(binary, token) {
                TypeRef::Base(t) => t,
                TypeRef::ImmRef(t) => t,
                TypeRef::MutRef(t) => t,
            };

            // TODO: assumed no type arguments above for simplicity
            let ty_base = registry.instantiate_type_tag(&ty_tag, &[]);
            let ty_runtime = Self::convert_type_base(registry, &ty_base);
            param_types.push((ty_base, ty_runtime));
        }
        param_types
    }

    fn convert_type_base(registry: &DatatypeRegistry, ty_base: &TypeBase) -> RuntimeType {
        match ty_base {
            TypeBase::Bool => RuntimeType::Bool,
            TypeBase::U8 => RuntimeType::U8,
            TypeBase::U16 => RuntimeType::U16,
            TypeBase::U32 => RuntimeType::U32,
            TypeBase::U64 => RuntimeType::U64,
            TypeBase::U128 => RuntimeType::U128,
            TypeBase::U256 => RuntimeType::U256,
            TypeBase::Bitvec => RuntimeType::Bitvec,
            TypeBase::String => RuntimeType::String,
            TypeBase::Address => RuntimeType::Address,
            TypeBase::Signer => RuntimeType::Signer,
            TypeBase::Option { element } => {
                RuntimeType::Option(Self::convert_type_base(registry, element).into())
            },
            TypeBase::Vector { element, variant } => {
                // TODO: we do not assume other vector types to appear as entry parameter
                assert!(matches!(variant, VectorVariant::Vector));
                RuntimeType::Vector(Self::convert_type_base(registry, element).into())
            },
            TypeBase::Map { .. } => {
                // TODO: we do not assume map types to appear as entry parameter
                panic!("intrinsic map type is not expected to appear as entry parameter");
            },
            TypeBase::Datatype {
                ident,
                type_args,
                abilities: _,
            } => {
                let (decl, content) = registry.lookup_decl_and_content(&ident);
                assert_eq!(decl.generics.len(), type_args.len());

                let datatype_content = match content {
                    DatatypeContent::Fields(fields) => {
                        let tys: Vec<_> = fields
                            .iter()
                            .map(|t| {
                                Self::convert_type_base(
                                    registry,
                                    &registry.instantiate_type_tag(t, type_args),
                                )
                            })
                            .collect();
                        vec![tys]
                    },
                    DatatypeContent::Variants(variants) => variants
                        .values()
                        .map(|fields| {
                            fields
                                .iter()
                                .map(|t| {
                                    Self::convert_type_base(
                                        registry,
                                        &registry.instantiate_type_tag(t, type_args),
                                    )
                                })
                                .collect()
                        })
                        .collect(),
                };
                RuntimeType::Datatype(datatype_content)
            },
            TypeBase::Object {
                ident,
                type_args,
                abilities: _,
            } => RuntimeType::Object(ident.clone(), type_args.clone()),
        }
    }
}
