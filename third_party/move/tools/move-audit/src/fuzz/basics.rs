use crate::{
    common::{Account, PkgDefinition},
    deps::PkgManifest,
    fuzz::{
        ident::{DatatypeIdent, FunctionIdent},
        typing::{DatatypeContent, DatatypeRegistry, TypeBase, TypeRef, VectorVariant},
    },
    package, LanguageSetting,
};
use move_binary_format::{
    access::{ModuleAccess, ScriptAccess},
    binary_views::BinaryIndexedView,
    file_format::{CompiledScript, Signature, Visibility},
};
use move_compiler::compiled_unit::{CompiledUnit, CompiledUnitEnum};
use move_core_types::value::{MoveStructLayout, MoveTypeLayout};
use move_package::compilation::compiled_package::CompiledUnitWithSource;
use std::{collections::BTreeMap, fmt::Display, fs};

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
    params: Vec<(TypeRef, RuntimeType)>,
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
    Struct(Vec<Self>),
    Enum(Vec<Vec<Self>>),
}

impl<'a> Into<MoveTypeLayout> for &'a RuntimeType {
    fn into(self) -> MoveTypeLayout {
        match self {
            RuntimeType::Bool => MoveTypeLayout::Bool,
            RuntimeType::U8 => MoveTypeLayout::U8,
            RuntimeType::U16 => MoveTypeLayout::U16,
            RuntimeType::U32 => MoveTypeLayout::U32,
            RuntimeType::U64 => MoveTypeLayout::U64,
            RuntimeType::U128 => MoveTypeLayout::U128,
            RuntimeType::U256 => MoveTypeLayout::U256,
            RuntimeType::Bitvec => MoveTypeLayout::Vector(MoveTypeLayout::Bool.into()),
            RuntimeType::String => MoveTypeLayout::Vector(MoveTypeLayout::U8.into()),
            RuntimeType::Address => MoveTypeLayout::Address,
            RuntimeType::Signer => MoveTypeLayout::Signer,
            RuntimeType::Option(inner) => MoveTypeLayout::Vector(Box::new(inner.as_ref().into())),
            RuntimeType::Vector(inner) => MoveTypeLayout::Vector(Box::new(inner.as_ref().into())),
            RuntimeType::Object(..) => MoveTypeLayout::Address,
            RuntimeType::Struct(fields) => MoveTypeLayout::Struct(MoveStructLayout::Runtime(
                fields.iter().map(|f| f.into()).collect(),
            )),
            RuntimeType::Enum(variants) => {
                MoveTypeLayout::Struct(MoveStructLayout::RuntimeVariants(
                    variants
                        .iter()
                        .map(|variant| variant.iter().map(|f| f.into()).collect())
                        .collect(),
                ))
            },
        }
    }
}

/// Captures all pre-fuzzing preparation
pub struct Preparer {
    /// a database of entry-points
    entrypoints: BTreeMap<EntrypointIdent, EntrypointDetails>,
    /// scripts that are coupled in the package
    scripts_coupled: BTreeMap<String, CompiledScript>,
    /// scripts that are generated
    scripts_autogen: BTreeMap<FunctionIdent, CompiledScript>,
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
        let mut scripts_coupled = BTreeMap::new();
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
                        let exists =
                            scripts_coupled.insert(script.name.to_string(), script.script.clone());
                        assert!(exists.is_none());

                        let ident = EntrypointIdent::Script(script.name.to_string());
                        let script = &script.script;
                        let binary = BinaryIndexedView::Script(script);

                        // NOTE: assuming no generic types for simplification
                        // TODO: remove this simplification
                        assert!(script.type_parameters.is_empty());

                        let mut params = vec![];
                        for (ty_ref, ty_base, ty_runtime) in Self::convert_signature(
                            &datatype_registry,
                            &binary,
                            script.signature_at(script.parameters),
                        ) {
                            // sanity check
                            assert!(
                                matches!(ty_base, TypeBase::Signer)
                                    || ty_base.abilities().has_copy()
                            );
                            params.push((ty_ref, ty_runtime));
                        }

                        // register to the entrypoint mapping
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
                            for (ty_ref, ty_base, ty_runtime) in Self::convert_signature(
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
                                params.push((ty_ref, ty_runtime));
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

                            // register to the entrypoint mapping
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

        // done with the provision
        log::info!("entrypoints discovered: {}", entrypoints.len());
        Self {
            entrypoints,
            scripts_coupled,
            scripts_autogen: BTreeMap::new(),
        }
    }

    fn convert_signature(
        registry: &DatatypeRegistry,
        binary: &BinaryIndexedView,
        params: &Signature,
    ) -> Vec<(TypeRef, TypeBase, RuntimeType)> {
        let mut param_types = vec![];
        for token in params.0.iter() {
            let ty_ref = registry.convert_signature_token(binary, token);
            let ty_tag = match &ty_ref {
                TypeRef::Base(t) => t,
                TypeRef::ImmRef(t) => t,
                TypeRef::MutRef(t) => t,
            };

            // TODO: assumed no type arguments above for simplicity
            let ty_base = registry.instantiate_type_tag(ty_tag, &[]);
            let ty_runtime = Self::convert_type_base(registry, &ty_base);
            param_types.push((ty_ref, ty_base, ty_runtime));
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

                match content {
                    DatatypeContent::Fields(fields) => {
                        let tys = fields
                            .iter()
                            .map(|t| {
                                Self::convert_type_base(
                                    registry,
                                    &registry.instantiate_type_tag(t, type_args),
                                )
                            })
                            .collect();
                        RuntimeType::Struct(tys)
                    },
                    DatatypeContent::Variants(variants) => {
                        let tys = variants
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
                            .collect();
                        RuntimeType::Enum(tys)
                    },
                }
            },
            TypeBase::Object {
                ident,
                type_args,
                abilities: _,
            } => RuntimeType::Object(ident.clone(), type_args.clone()),
        }
    }

    /// Prepare and build the autogen package
    pub fn generate_scripts(
        &mut self,
        named_accounts: &BTreeMap<String, Account>,
        language: LanguageSetting,
        autogen_manifest: &PkgManifest,
    ) {
        // generate move scripts for all public functions (excluding public entry functions)
        let autogen_src = autogen_manifest.path.join("sources");
        assert!(autogen_src.is_dir());

        let mut script_to_ident = BTreeMap::new();
        for (ident, details) in &self.entrypoints {
            let ident = match ident {
                EntrypointIdent::PublicFunction(ident) => ident,
                EntrypointIdent::Script(_) | EntrypointIdent::EntryFunction(_) => continue,
            };

            // generate argument definition and usage
            let mut param_decls = vec![];
            let mut arg_uses = vec![];
            for (i, (ty_ref, _)) in details.params.iter().enumerate() {
                let name = format!("p{i}");
                param_decls.push(format!("{name}: {ty_ref}"));
                arg_uses.push(name);
            }

            // compose the script
            let script_name = format!("script_{}_{}", ident.module_name(), ident.function_name());
            let script = format!(
                r#"
script {{
    fun {script_name}({}) {{
        {ident}({});
    }}
}}
"#,
                param_decls.join(","),
                arg_uses.join(","),
            );

            // save the script to the autogen package
            let script_path = autogen_src.join(format!("{script_name}.move"));
            assert!(!script_path.exists());
            fs::write(&script_path, &script).expect("failed to write script file");

            // save the mapping
            script_to_ident.insert(script_path, ident.clone());
        }

        // compile this autogen module
        let pkg_built = package::build(autogen_manifest, named_accounts, language, false)
            .unwrap_or_else(|why| panic!("unable to build the autogen package: {why}"));
        log::info!("autogen package built successfully");

        // get the scripts
        for unit in pkg_built.package.root_compiled_units {
            let path = unit.source_path;
            match unit.unit {
                CompiledUnitEnum::Module(_) => panic!("unexpected module in the autogen package"),
                CompiledUnitEnum::Script(script) => {
                    let ident = script_to_ident.remove(&path).unwrap_or_else(|| {
                        panic!("failed to find the ident for script {}", script.name)
                    });
                    let exists = self.scripts_autogen.insert(ident, script.script);
                    assert!(exists.is_none());
                },
            }
        }
    }
}
