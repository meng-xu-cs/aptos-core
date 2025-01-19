use crate::fuzz::ident::DatatypeIdent;
use move_binary_format::{
    access::ModuleAccess,
    file_format::{AbilitySet, SignatureToken},
    CompiledModule,
};
use move_core_types::account_address::AccountAddress;
use std::collections::BTreeMap;

/// Variants of vector implementation
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum VectorVariant {
    Vector,
    BigVector,
    SmartVector,
}

/// Variants of map implementation
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum MapVariant {
    Table,
    TableWithLength,
    SmartTable,
    SimpleMap,
    OrderedMap,
    BigOrderedMap,
}

/// A concrete type instance within a typing context
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeTag {
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
    Vector {
        element: Box<Self>,
        variant: VectorVariant,
    },
    Map {
        key: Box<Self>,
        value: Box<Self>,
        variant: MapVariant,
    },
    Datatype(DatatypeInst),
    Param(usize),
}

/// A type that can appear in function declarations
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeRef {
    Owned(TypeTag),
    ImmRef(TypeTag),
    MutRef(TypeTag),
}

/// Instantiation of a datatype
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct DatatypeInst {
    ident: DatatypeIdent,
    type_args: Vec<TypeTag>,
}

/// Intrinsic datatypes known and specially handled
pub enum IntrinsicType {
    Bitvec,
    String,
    Vector(VectorVariant),
    Map(MapVariant),
}

impl IntrinsicType {
    pub fn try_parse_ident(ident: &DatatypeIdent) -> Option<Self> {
        if ident.address() != AccountAddress::ONE {
            return None;
        }
        let parsed = match (ident.module_name(), ident.datatype_name()) {
            ("bit_vector", "BitVector") => IntrinsicType::Bitvec,
            ("string", "String") => IntrinsicType::String,
            ("big_vector", "BigVector") => IntrinsicType::Vector(VectorVariant::BigVector),
            ("smart_vector", "SmartVector") => IntrinsicType::Vector(VectorVariant::SmartVector),
            ("table", "Table") => IntrinsicType::Map(MapVariant::Table),
            ("table_with_length", "TableWithLength") => {
                IntrinsicType::Map(MapVariant::TableWithLength)
            },
            ("smart_table", "SmartTable") => IntrinsicType::Map(MapVariant::SmartTable),
            ("simple_map", "SimpleMap") => IntrinsicType::Map(MapVariant::SimpleMap),
            ("ordered_map", "OrderedMap") => IntrinsicType::Map(MapVariant::OrderedMap),
            ("big_ordered_map", "BigOrderedMap") => IntrinsicType::Map(MapVariant::BigOrderedMap),
            _ => return None,
        };
        Some(parsed)
    }
}

/// Declaration of a datatype
pub struct DatatypeDecl {
    pub ident: DatatypeIdent,
    pub generics: Vec<(AbilitySet, bool)>,
    pub abilities: AbilitySet,
    is_primary: bool,
}

impl DatatypeDecl {
    /// Check whether this datatype is defined in the primary target
    pub fn is_primary(&self) -> bool {
        self.is_primary
    }
}

/// A registry of datatypes
pub struct DatatypeRegistry {
    decls: BTreeMap<DatatypeIdent, DatatypeDecl>,
}

impl DatatypeRegistry {
    /// Create an empty registry
    pub fn new() -> Self {
        Self {
            decls: BTreeMap::new(),
        }
    }

    /// Analyze a module and register datatypes found in this module
    pub fn analyze(&mut self, module: &CompiledModule, is_primary: bool) {
        // go over all structs defined
        for def in &module.struct_defs {
            let handle = module.struct_handle_at(def.struct_handle);
            let ident = DatatypeIdent::from_struct_handle(module, handle);

            // skip intrinsic types
            if IntrinsicType::try_parse_ident(&ident).is_some() {
                continue;
            }

            // add the declaration
            let decl = DatatypeDecl {
                ident: ident.clone(),
                generics: handle
                    .type_parameters
                    .iter()
                    .map(|p| (p.constraints, p.is_phantom))
                    .collect(),
                abilities: handle.abilities,
                is_primary,
            };
            let existing = self.decls.insert(ident, decl);
            assert!(existing.is_none());
        }
    }

    /// Convert a signature token
    pub fn convert_signature_token(
        &self,
        module: &CompiledModule,
        token: &SignatureToken,
    ) -> TypeRef {
        match token {
            SignatureToken::Bool => TypeRef::Owned(TypeTag::Bool),
            SignatureToken::U8 => TypeRef::Owned(TypeTag::U8),
            SignatureToken::U16 => TypeRef::Owned(TypeTag::U16),
            SignatureToken::U32 => TypeRef::Owned(TypeTag::U32),
            SignatureToken::U64 => TypeRef::Owned(TypeTag::U64),
            SignatureToken::U128 => TypeRef::Owned(TypeTag::U128),
            SignatureToken::U256 => TypeRef::Owned(TypeTag::U256),
            SignatureToken::Address => TypeRef::Owned(TypeTag::Address),
            SignatureToken::Signer => TypeRef::Owned(TypeTag::Signer),
            SignatureToken::Vector(element) => {
                let element_tag = match self.convert_signature_token(module, element) {
                    TypeRef::Owned(tag) => tag,
                    TypeRef::ImmRef(_) | TypeRef::MutRef(_) => {
                        panic!("reference type as vector element is not expected");
                    },
                };
                TypeRef::Owned(TypeTag::Vector {
                    element: element_tag.into(),
                    variant: VectorVariant::Vector,
                })
            },
            SignatureToken::Struct(idx) => {
                let handle = module.struct_handle_at(*idx);
                let ident = DatatypeIdent::from_struct_handle(module, handle);

                // first try to see if this is an intrinsic type
                match IntrinsicType::try_parse_ident(&ident) {
                    Some(IntrinsicType::Bitvec) => TypeRef::Owned(TypeTag::Bitvec),
                    Some(IntrinsicType::String) => TypeRef::Owned(TypeTag::String),
                    Some(IntrinsicType::Vector(_)) | Some(IntrinsicType::Map(_)) => {
                        panic!("parameterized intrinsic type is not expected to be `SignatureToken::Struct`");
                    },
                    None => {
                        // not an intrinsic type, locate the datatype
                        let decl = self
                            .decls
                            .get(&ident)
                            .unwrap_or_else(|| panic!("unregistered datatype {ident}"));
                        assert!(decl.generics.is_empty());
                        TypeRef::Owned(TypeTag::Datatype(DatatypeInst {
                            ident,
                            type_args: vec![],
                        }))
                    },
                }
            },
            SignatureToken::StructInstantiation(idx, inst) => {
                let handle = module.struct_handle_at(*idx);
                let ident = DatatypeIdent::from_struct_handle(module, handle);

                // convert the type arguments
                let mut ty_args: Vec<_> = inst
                    .iter()
                    .map(|t| match self.convert_signature_token(module, t) {
                        TypeRef::Owned(tag) => tag,
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
                    Some(IntrinsicType::Vector(variant)) => {
                        assert_eq!(ty_args.len(), 1);
                        TypeRef::Owned(TypeTag::Vector {
                            element: ty_args.pop().unwrap().into(),
                            variant,
                        })
                    },
                    Some(IntrinsicType::Map(variant)) => {
                        assert_eq!(ty_args.len(), 2);
                        TypeRef::Owned(TypeTag::Map {
                            key: ty_args.pop().unwrap().into(),
                            value: ty_args.pop().unwrap().into(),
                            variant,
                        })
                    },
                    None => {
                        // not an intrinsic type, locate the datatype
                        let decl = self
                            .decls
                            .get(&ident)
                            .unwrap_or_else(|| panic!("unregistered datatype {ident}"));
                        assert_eq!(decl.generics.len(), ty_args.len());
                        TypeRef::Owned(TypeTag::Datatype(DatatypeInst {
                            ident,
                            type_args: ty_args,
                        }))
                    },
                }
            },
            SignatureToken::Reference(inner) => {
                let inner_tag = match self.convert_signature_token(module, inner) {
                    TypeRef::Owned(tag) => tag,
                    TypeRef::ImmRef(_) | TypeRef::MutRef(_) => {
                        panic!("reference type behind immutable borrow is not expected");
                    },
                };
                TypeRef::ImmRef(inner_tag)
            },
            SignatureToken::MutableReference(inner) => {
                let inner_tag = match self.convert_signature_token(module, inner) {
                    TypeRef::Owned(tag) => tag,
                    TypeRef::ImmRef(_) | TypeRef::MutRef(_) => {
                        panic!("reference type behind mutable borrow is not expected");
                    },
                };
                TypeRef::MutRef(inner_tag)
            },
            SignatureToken::TypeParameter(idx) => TypeRef::Owned(TypeTag::Param(*idx as usize)),
        }
    }

    /// Find all declarations that match the ability requirement
    pub fn datatypes_by_ability_constraint(&self, constraint: AbilitySet) -> Vec<DatatypeIdent> {
        for decl in self.decls.values() {
            // short-circuit if the constraint is not met
            if !constraint.is_subset(decl.abilities) {
                continue;
            }

            // try to instantiate
            todo!()
        }
        todo!()
    }

    /// Find all type tags that match the ability requirement
    pub fn type_tags_by_ability_constraint(&self, constraint: AbilitySet) -> Vec<TypeTag> {
        let mut result = vec![];
        if constraint.is_subset(AbilitySet::PRIMITIVES) {
            result.push(TypeTag::Bool);
            result.push(TypeTag::U8);
            result.push(TypeTag::U16);
            result.push(TypeTag::U32);
            result.push(TypeTag::U64);
            result.push(TypeTag::U128);
            result.push(TypeTag::U256);
            result.push(TypeTag::Bitvec);
            result.push(TypeTag::String);
            result.push(TypeTag::Address);
        }
        if constraint.is_subset(AbilitySet::SIGNER) {
            result.push(TypeTag::Signer);
        }
        result
    }

    /// Find all type refs that match the ability requirement
    pub fn type_refs_by_ability_constraint(&self, constraint: AbilitySet) -> Vec<TypeRef> {
        let mut result = self
            .type_tags_by_ability_constraint(constraint)
            .into_iter()
            .map(TypeRef::Owned)
            .collect();

        if constraint.is_subset(AbilitySet::REFERENCES) {
            let _ = self
                .type_tags_by_ability_constraint(AbilitySet::EMPTY)
                .into_iter()
                .map(TypeRef::ImmRef);
            todo!()
        }
        result
    }
}
