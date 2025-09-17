// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    deps::PkgKind,
    prep::{
        ident::DatatypeIdent,
        typing::{IntrinsicType, TypeBase, TypeItem, TypeRef, TypeTag, VectorVariant},
    },
};
use move_binary_format::{
    binary_views::BinaryIndexedView,
    file_format::{SignatureToken, StructFieldInformation},
    CompiledModule,
};
use move_core_types::ability::AbilitySet;
use std::collections::BTreeMap;

/// Declaration of a datatype
pub struct DatatypeDecl {
    pub ident: DatatypeIdent,
    pub generics: Vec<(AbilitySet, bool)>,
    pub abilities: AbilitySet,
    pub kind: PkgKind,
}

/// Content of a datatype
pub enum DatatypeContent {
    Fields(Vec<TypeTag>),
    Variants(BTreeMap<String, Vec<TypeTag>>),
}

/// A registry of datatypes
pub struct DatatypeRegistry {
    decls: BTreeMap<DatatypeIdent, DatatypeDecl>,
    contents: BTreeMap<DatatypeIdent, DatatypeContent>,
}

impl DatatypeRegistry {
    /// Create an empty registry
    pub fn new() -> Self {
        Self {
            decls: BTreeMap::new(),
            contents: BTreeMap::new(),
        }
    }

    /// Analyze a module and register datatypes found in this module
    pub fn analyze(&mut self, module: &CompiledModule, kind: PkgKind) {
        let binary = BinaryIndexedView::Module(module);

        // pass 1: register declarations
        for def in &module.struct_defs {
            let handle = binary.struct_handle_at(def.struct_handle);
            let ident = DatatypeIdent::from_struct_handle(&binary, handle);

            // skip intrinsic types
            if IntrinsicType::try_parse_ident(&ident).is_some() {
                continue;
            }

            // register the declaration
            let decl = DatatypeDecl {
                ident: ident.clone(),
                generics: handle
                    .type_parameters
                    .iter()
                    .map(|p| (p.constraints, p.is_phantom))
                    .collect(),
                abilities: handle.abilities,
                kind,
            };
            let existing = self.decls.insert(ident, decl);
            assert!(existing.is_none());
        }

        // pass 2: fill in content
        for def in &module.struct_defs {
            let handle = binary.struct_handle_at(def.struct_handle);
            let ident = DatatypeIdent::from_struct_handle(&binary, handle);

            // skip intrinsic types
            if IntrinsicType::try_parse_ident(&ident).is_some() {
                continue;
            }

            // parse the content
            let content = match &def.field_information {
                StructFieldInformation::Native => panic!("unexpected native datatype {ident}"),
                StructFieldInformation::Declared(fields) => {
                    let mut field_types = vec![];
                    for field_def in fields.iter() {
                        let tag =
                            match self.convert_signature_token(&binary, &field_def.signature.0) {
                                TypeRef::Base(tag) => tag,
                                TypeRef::ImmRef(_) | TypeRef::MutRef(_) => {
                                    panic!("unexpected reference type as struct field");
                                },
                            };
                        field_types.push(tag);
                    }
                    DatatypeContent::Fields(field_types)
                },
                StructFieldInformation::DeclaredVariants(variants) => {
                    let mut variant_table = BTreeMap::new();
                    for variant_def in variants {
                        let key = binary.identifier_at(variant_def.name).to_string();
                        let mut field_types = vec![];
                        for field_def in variant_def.fields.iter() {
                            let tag = match self
                                .convert_signature_token(&binary, &field_def.signature.0)
                            {
                                TypeRef::Base(tag) => tag,
                                TypeRef::ImmRef(_) | TypeRef::MutRef(_) => {
                                    panic!("unexpected reference type as enum variant");
                                },
                            };
                            field_types.push(tag);
                        }
                        let existing = variant_table.insert(key, field_types);
                        assert!(existing.is_none());
                    }
                    DatatypeContent::Variants(variant_table)
                },
            };

            // register the content
            let existing = self.contents.insert(ident, content);
            assert!(existing.is_none());
        }

        // sanity check
        assert_eq!(self.decls.len(), self.contents.len());
        self.decls
            .keys()
            .zip(self.contents.keys())
            .for_each(|(ident_decl, ident_content)| assert_eq!(ident_decl, ident_content));
    }

    /// Lookup a datatype declaration
    pub fn lookup_decl(&self, ident: &DatatypeIdent) -> &DatatypeDecl {
        self.decls
            .get(ident)
            .unwrap_or_else(|| panic!("unregistered datatype {ident}"))
    }

    /// Lookup a datatype declaration
    pub fn lookup_decl_and_content(
        &self,
        ident: &DatatypeIdent,
    ) -> (&DatatypeDecl, &DatatypeContent) {
        let decl = self
            .decls
            .get(ident)
            .unwrap_or_else(|| panic!("unregistered datatype {ident}"));
        let content = self
            .contents
            .get(ident)
            .unwrap_or_else(|| panic!("unregistered datatype {ident}"));
        (decl, content)
    }

    /// Convert a signature token
    pub fn convert_signature_token(
        &self,
        binary: &BinaryIndexedView,
        token: &SignatureToken,
    ) -> TypeRef {
        match token {
            SignatureToken::Bool => TypeRef::Base(TypeTag::Bool),
            SignatureToken::U8 => TypeRef::Base(TypeTag::U8),
            SignatureToken::I8 => TypeRef::Base(TypeTag::I8),
            SignatureToken::U16 => TypeRef::Base(TypeTag::U16),
            SignatureToken::I16 => TypeRef::Base(TypeTag::I16),
            SignatureToken::U32 => TypeRef::Base(TypeTag::U32),
            SignatureToken::I32 => TypeRef::Base(TypeTag::I32),
            SignatureToken::U64 => TypeRef::Base(TypeTag::U64),
            SignatureToken::I64 => TypeRef::Base(TypeTag::I64),
            SignatureToken::U128 => TypeRef::Base(TypeTag::U128),
            SignatureToken::I128 => TypeRef::Base(TypeTag::I128),
            SignatureToken::U256 => TypeRef::Base(TypeTag::U256),
            SignatureToken::I256 => TypeRef::Base(TypeTag::I256),
            SignatureToken::Address => TypeRef::Base(TypeTag::Address),
            SignatureToken::Signer => TypeRef::Base(TypeTag::Signer),
            SignatureToken::Vector(element) => {
                let element_tag = match self.convert_signature_token(binary, element) {
                    TypeRef::Base(tag) => tag,
                    TypeRef::ImmRef(_) | TypeRef::MutRef(_) => {
                        panic!("reference type as vector element is not expected");
                    },
                };
                TypeRef::Base(TypeTag::Vector {
                    element: element_tag.into(),
                    variant: VectorVariant::Vector,
                })
            },
            SignatureToken::Struct(idx) => {
                let handle = binary.struct_handle_at(*idx);
                let ident = DatatypeIdent::from_struct_handle(binary, handle);

                // first try to see if this is an intrinsic type
                match IntrinsicType::try_parse_ident(&ident) {
                    Some(IntrinsicType::Bitvec) => TypeRef::Base(TypeTag::Bitvec),
                    Some(IntrinsicType::String) => TypeRef::Base(TypeTag::String),
                    Some(IntrinsicType::Option)
                    | Some(IntrinsicType::Vector(_))
                    | Some(IntrinsicType::Map(_))
                    | Some(IntrinsicType::Object) => {
                        panic!("parameterized intrinsic type is not expected to be `SignatureToken::Struct`");
                    },
                    None => {
                        // not an intrinsic type, locate the datatype
                        let decl = self.lookup_decl(&ident);
                        assert!(decl.generics.is_empty());
                        TypeRef::Base(TypeTag::Datatype {
                            ident,
                            type_args: vec![],
                        })
                    },
                }
            },
            SignatureToken::StructInstantiation(idx, inst) => {
                let handle = binary.struct_handle_at(*idx);
                let ident = DatatypeIdent::from_struct_handle(binary, handle);

                // convert the type arguments
                let mut ty_args: Vec<_> = inst
                    .iter()
                    .map(|t| match self.convert_signature_token(binary, t) {
                        TypeRef::Base(tag) => tag,
                        TypeRef::ImmRef(_) | TypeRef::MutRef(_) => {
                            panic!("reference type as datatype instantiation is not expected");
                        },
                    })
                    .collect();

                // first try to see if this is an intrinsic type
                match IntrinsicType::try_parse_ident(&ident) {
                    Some(IntrinsicType::Bitvec) | Some(IntrinsicType::String) => {
                        panic!("basic intrinsic type is not expected to be `SignatureToken::StructInstantiation`");
                    },
                    Some(IntrinsicType::Option) => {
                        assert_eq!(ty_args.len(), 1);
                        TypeRef::Base(TypeTag::Option {
                            element: ty_args.pop().unwrap().into(),
                        })
                    },
                    Some(IntrinsicType::Vector(variant)) => {
                        assert_eq!(ty_args.len(), 1);
                        TypeRef::Base(TypeTag::Vector {
                            element: ty_args.pop().unwrap().into(),
                            variant,
                        })
                    },
                    Some(IntrinsicType::Map(variant)) => {
                        assert_eq!(ty_args.len(), 2);
                        TypeRef::Base(TypeTag::Map {
                            key: ty_args.pop().unwrap().into(),
                            value: ty_args.pop().unwrap().into(),
                            variant,
                        })
                    },
                    Some(IntrinsicType::Object) => {
                        assert_eq!(ty_args.len(), 1);
                        match ty_args.pop().unwrap() {
                            TypeTag::Datatype { ident, type_args } => {
                                TypeRef::Base(TypeTag::ObjectKnown { ident, type_args })
                            },
                            TypeTag::Param(index) => TypeRef::Base(TypeTag::ObjectParam(index)),
                            _ => panic!("type argument for Object must be a datatype or parameter"),
                        }
                    },
                    None => {
                        // not an intrinsic type, locate the datatype
                        let decl = self.lookup_decl(&ident);
                        assert_eq!(decl.generics.len(), ty_args.len());
                        TypeRef::Base(TypeTag::Datatype {
                            ident,
                            type_args: ty_args,
                        })
                    },
                }
            },
            SignatureToken::Reference(inner) => {
                let inner_tag = match self.convert_signature_token(binary, inner) {
                    TypeRef::Base(tag) => tag,
                    TypeRef::ImmRef(_) | TypeRef::MutRef(_) => {
                        panic!("reference type behind immutable borrow is not expected");
                    },
                };
                TypeRef::ImmRef(inner_tag)
            },
            SignatureToken::MutableReference(inner) => {
                let inner_tag = match self.convert_signature_token(binary, inner) {
                    TypeRef::Base(tag) => tag,
                    TypeRef::ImmRef(_) | TypeRef::MutRef(_) => {
                        panic!("reference type behind mutable borrow is not expected");
                    },
                };
                TypeRef::MutRef(inner_tag)
            },
            SignatureToken::TypeParameter(idx) => TypeRef::Base(TypeTag::Param(*idx as usize)),
            SignatureToken::Function(..) => {
                todo!("signature token of the `function` type is not supported yet")
            },
        }
    }

    /// Instantiate type parameters in this type tag with the type arguments
    pub fn instantiate_type_tag(&self, tag: &TypeTag, ty_args: &[TypeBase]) -> TypeBase {
        match tag {
            TypeTag::Bool => TypeBase::Bool,
            TypeTag::U8 => TypeBase::U8,
            TypeTag::I8 => TypeBase::I8,
            TypeTag::U16 => TypeBase::U16,
            TypeTag::I16 => TypeBase::I16,
            TypeTag::U32 => TypeBase::U32,
            TypeTag::I32 => TypeBase::I32,
            TypeTag::U64 => TypeBase::U64,
            TypeTag::I64 => TypeBase::I64,
            TypeTag::U128 => TypeBase::U128,
            TypeTag::I128 => TypeBase::I128,
            TypeTag::U256 => TypeBase::U256,
            TypeTag::I256 => TypeBase::I256,
            TypeTag::Bitvec => TypeBase::Bitvec,
            TypeTag::String => TypeBase::String,
            TypeTag::Address => TypeBase::Address,
            TypeTag::Signer => TypeBase::Signer,
            TypeTag::Option { element } => TypeBase::Option {
                element: self.instantiate_type_tag(element, ty_args).into(),
            },
            TypeTag::Vector { element, variant } => TypeBase::Vector {
                element: self.instantiate_type_tag(element, ty_args).into(),
                variant: *variant,
            },
            TypeTag::Map {
                key,
                value,
                variant,
            } => TypeBase::Map {
                key: self.instantiate_type_tag(key, ty_args).into(),
                value: self.instantiate_type_tag(value, ty_args).into(),
                variant: *variant,
            },
            TypeTag::Datatype { ident, type_args } => {
                let decl = self.lookup_decl(ident);
                debug_assert_eq!(type_args.len(), decl.generics.len());

                if type_args.is_empty() {
                    TypeBase::Datatype {
                        ident: ident.clone(),
                        type_args: vec![],
                        abilities: decl.abilities,
                    }
                } else {
                    let ty_args: Vec<_> = type_args
                        .iter()
                        .map(|t| self.instantiate_type_tag(t, ty_args))
                        .collect();
                    let actual_abilities = derive_actual_ability(decl, &ty_args);
                    TypeBase::Datatype {
                        ident: ident.clone(),
                        type_args: ty_args,
                        abilities: actual_abilities,
                    }
                }
            },
            TypeTag::Param(index) => ty_args
                .get(*index)
                .expect("type arguments in bound")
                .clone(),
            TypeTag::ObjectKnown { ident, type_args } => {
                let decl = self.lookup_decl(ident);
                assert_eq!(type_args.len(), decl.generics.len());

                if type_args.is_empty() {
                    TypeBase::ObjectKnown {
                        ident: ident.clone(),
                        type_args: vec![],
                        abilities: decl.abilities,
                    }
                } else {
                    let ty_args: Vec<_> = type_args
                        .iter()
                        .map(|t| self.instantiate_type_tag(t, ty_args))
                        .collect();
                    let actual_abilities = derive_actual_ability(decl, &ty_args);
                    TypeBase::ObjectKnown {
                        ident: ident.clone(),
                        type_args: ty_args,
                        abilities: actual_abilities,
                    }
                }
            },
            TypeTag::ObjectParam(index) => {
                match ty_args.get(*index).expect("type arguments in bound") {
                    TypeBase::Param { index, abilities } => TypeBase::ObjectParam {
                        index: *index,
                        abilities: *abilities,
                    },
                    TypeBase::Datatype {
                        ident,
                        type_args,
                        abilities,
                    } => TypeBase::ObjectKnown {
                        ident: ident.clone(),
                        type_args: type_args.clone(),
                        abilities: *abilities,
                    },
                    _ => panic!("expect a datatype or a parameter as the type argument for object"),
                }
            },
        }
    }

    /// Instantiate type parameters in this type ref with the type arguments
    pub fn instantiate_type_ref(&self, t: &TypeRef, ty_args: &[TypeBase]) -> TypeItem {
        match t {
            TypeRef::Base(tag) => TypeItem::Base(self.instantiate_type_tag(tag, ty_args)),
            TypeRef::ImmRef(tag) => TypeItem::ImmRef(self.instantiate_type_tag(tag, ty_args)),
            TypeRef::MutRef(tag) => TypeItem::MutRef(self.instantiate_type_tag(tag, ty_args)),
        }
    }
}

/// Utility: derive the actual ability based on type arguments
fn derive_actual_ability(decl: &DatatypeDecl, ty_args: &[TypeBase]) -> AbilitySet {
    let mut provided_abilities = AbilitySet::ALL;
    for (t, (_, is_phantom)) in ty_args.iter().zip(decl.generics.iter()) {
        if *is_phantom {
            continue;
        }
        provided_abilities = provided_abilities.intersect(t.abilities());
    }

    let mut actual_abilities = AbilitySet::EMPTY;
    for ability in decl.abilities.iter() {
        let required = ability.requires();
        if provided_abilities.has_ability(required) {
            actual_abilities = actual_abilities | ability;
        }
    }
    actual_abilities
}
