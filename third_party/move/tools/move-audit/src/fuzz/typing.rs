use crate::fuzz::ident::DatatypeIdent;
use itertools::Itertools;
use move_binary_format::{
    access::ModuleAccess,
    file_format::{Ability, AbilitySet, SignatureToken},
    CompiledModule,
};
use move_core_types::account_address::AccountAddress;
use std::{collections::BTreeMap, fmt::Display};

/// Variants of vector implementation
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum VectorVariant {
    Vector,
    BigVector,
    SmartVector,
}

impl VectorVariant {
    /// The declared abilities of this vector variant
    pub fn abilities(&self) -> AbilitySet {
        match self {
            Self::Vector => AbilitySet::VECTOR,
            Self::BigVector | Self::SmartVector => AbilitySet::EMPTY | Ability::Store,
        }
    }

    /// The ability constraint of the type parameter representing the element
    pub fn type_param_element(&self) -> AbilitySet {
        match self {
            Self::Vector => AbilitySet::EMPTY,
            Self::BigVector | Self::SmartVector => AbilitySet::EMPTY | Ability::Store,
        }
    }
}

impl Display for VectorVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vector => write!(f, "vector"),
            Self::BigVector => write!(f, "aptos_std::big_vector::BigVector"),
            Self::SmartVector => write!(f, "aptos_std::smart_vector::SmartVector"),
        }
    }
}

const VECTOR_VARIANTS: &[VectorVariant] = &[
    VectorVariant::Vector,
    VectorVariant::BigVector,
    VectorVariant::SmartVector,
];

/// Variants of map implementation
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum MapVariant {
    Table,
    TableWithLength,
    SmartTable,
    SimpleMap,
    OrderedMap,
    BigOrderedMap,
}

impl MapVariant {
    /// The declared abilities of this map variant
    pub fn abilities(&self) -> AbilitySet {
        match self {
            Self::Table | Self::TableWithLength | Self::SmartTable | Self::BigOrderedMap => {
                AbilitySet::EMPTY | Ability::Store
            },
            Self::SimpleMap | Self::OrderedMap => {
                AbilitySet::EMPTY | Ability::Copy | Ability::Drop | Ability::Store
            },
        }
    }

    /// The ability constraint of the type parameter representing the key
    pub fn type_param_key(&self) -> AbilitySet {
        match self {
            Self::Table | Self::TableWithLength => {
                AbilitySet::EMPTY | Ability::Copy | Ability::Drop
            },
            Self::SmartTable => AbilitySet::EMPTY | Ability::Copy | Ability::Drop | Ability::Store,
            Self::SimpleMap | Self::BigOrderedMap => AbilitySet::EMPTY | Ability::Store,
            Self::OrderedMap => AbilitySet::EMPTY,
        }
    }

    /// The ability constraint of the type parameter representing the value
    pub fn type_param_value(&self) -> AbilitySet {
        match self {
            Self::Table
            | Self::TableWithLength
            | Self::SmartTable
            | Self::SimpleMap
            | Self::BigOrderedMap => AbilitySet::EMPTY | Ability::Store,
            Self::OrderedMap => AbilitySet::EMPTY,
        }
    }
}

impl Display for MapVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Table => write!(f, "aptos_std::table::Table"),
            Self::TableWithLength => write!(f, "aptos_std::table_with_length::TableWithLength"),
            Self::SmartTable => write!(f, "aptos_std::smart_table::SmartTable"),
            Self::SimpleMap => write!(f, "aptos_std::simple_map::SimpleMap"),
            Self::OrderedMap => write!(f, "aptos_std::ordered_map::OrderedMap"),
            Self::BigOrderedMap => write!(f, "aptos_std::big_ordered_map::BigOrderedMap"),
        }
    }
}

const MAP_VARIANTS: &[MapVariant] = &[
    MapVariant::Table,
    MapVariant::TableWithLength,
    MapVariant::SmartTable,
    MapVariant::SimpleMap,
    MapVariant::OrderedMap,
    MapVariant::BigOrderedMap,
];

/// A specific type instance within a typing context
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
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
    Datatype {
        ident: DatatypeIdent,
        type_args: Vec<Self>,
    },
    Param(usize),
}

impl Display for TypeTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool => write!(f, "bool"),
            Self::U8 => write!(f, "u8"),
            Self::U16 => write!(f, "u16"),
            Self::U32 => write!(f, "u32"),
            Self::U64 => write!(f, "u64"),
            Self::U128 => write!(f, "u128"),
            Self::U256 => write!(f, "u256"),
            Self::Bitvec => write!(f, "std::bit_vector::BitVector"),
            Self::String => write!(f, "std::string::String"),
            Self::Address => write!(f, "address"),
            Self::Signer => write!(f, "signer"),
            Self::Vector { variant, element } => write!(f, "{variant}<{element}>"),
            Self::Map {
                variant,
                key,
                value,
            } => write!(f, "{variant}<{key}, {value}>"),
            Self::Datatype { ident, type_args } => {
                if type_args.is_empty() {
                    write!(f, "{ident}")
                } else {
                    let inst = type_args.iter().join(", ");
                    write!(f, "{ident}<{inst}>")
                }
            },
            Self::Param(index) => write!(f, "#{index}"),
        }
    }
}

/// A type token that can appear in function declarations
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeRef {
    Base(TypeTag),
    ImmRef(TypeTag),
    MutRef(TypeTag),
}

impl Display for TypeRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base(tag) => write!(f, "{tag}"),
            Self::ImmRef(tag) => write!(f, "&{tag}"),
            Self::MutRef(tag) => write!(f, "&mut {tag}"),
        }
    }
}

/// Instantiation of a datatype
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
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
    pub is_primary: bool,
}

/// A type instance with concrete execution semantics
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeBase {
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
    Datatype {
        ident: DatatypeIdent,
        type_args: Vec<Self>,
        abilities: AbilitySet,
    },
}

impl TypeBase {
    /// Retrieve the abilities of this type base
    pub fn abilities(&self) -> AbilitySet {
        match self {
            Self::Bool
            | Self::U8
            | Self::U16
            | Self::U32
            | Self::U64
            | Self::U128
            | Self::U256
            | Self::Bitvec
            | Self::String
            | Self::Address => AbilitySet::PRIMITIVES,
            Self::Signer => AbilitySet::SIGNER,
            Self::Vector { element, variant } => {
                let mut actual_abilities = AbilitySet::EMPTY;
                let provided_abilities = element.abilities();
                for ability in variant.abilities() {
                    let required = ability.requires();
                    if provided_abilities.has_ability(required) {
                        actual_abilities = actual_abilities | ability;
                    }
                }
                actual_abilities
            },
            Self::Map {
                key,
                value,
                variant,
            } => {
                let mut actual_abilities = AbilitySet::EMPTY;
                let provided_abilities = key.abilities().intersect(value.abilities());
                for ability in variant.abilities() {
                    let required = ability.requires();
                    if provided_abilities.has_ability(required) {
                        actual_abilities = actual_abilities | ability;
                    }
                }
                actual_abilities
            },
            Self::Datatype {
                ident: _,
                type_args: _,
                abilities,
            } => *abilities,
        }
    }

    /// Check if a type base can be constructed trivially
    pub fn has_trivial_ctor(&self) -> bool {
        match self {
            Self::Bool
            | Self::U8
            | Self::U16
            | Self::U32
            | Self::U64
            | Self::U128
            | Self::U256
            | Self::Bitvec
            | Self::String
            | Self::Address
            | Self::Signer => true,
            Self::Vector {
                element,
                variant: _,
            } => element.has_trivial_ctor(),
            Self::Map {
                key,
                value,
                variant: _,
            } => key.has_trivial_ctor() && value.has_trivial_ctor(),
            Self::Datatype { .. } => false,
        }
    }

    /// Check if a type base can be destructed trivially
    pub fn has_trivial_dtor(&self) -> bool {
        self.abilities().has_drop()
    }
}

impl Display for TypeBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool => write!(f, "bool"),
            Self::U8 => write!(f, "u8"),
            Self::U16 => write!(f, "u16"),
            Self::U32 => write!(f, "u32"),
            Self::U64 => write!(f, "u64"),
            Self::U128 => write!(f, "u128"),
            Self::U256 => write!(f, "u256"),
            Self::Bitvec => write!(f, "std::bit_vector::BitVector"),
            Self::String => write!(f, "std::string::String"),
            Self::Address => write!(f, "address"),
            Self::Signer => write!(f, "signer"),
            Self::Vector { variant, element } => write!(f, "{variant}<{element}>"),
            Self::Map {
                variant,
                key,
                value,
            } => write!(f, "{variant}<{key}, {value}>"),
            Self::Datatype {
                ident,
                type_args,
                abilities: _,
            } => {
                if type_args.is_empty() {
                    write!(f, "{ident}")
                } else {
                    let inst = type_args.iter().join(", ");
                    write!(f, "{ident}<{inst}>")
                }
            },
        }
    }
}

/// A type token with concrete execution semantics
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeItem {
    Base(TypeBase),
    ImmRef(TypeBase),
    MutRef(TypeBase),
}

impl Display for TypeItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Base(base) => write!(f, "{base}"),
            Self::ImmRef(base) => write!(f, "&{base}"),
            Self::MutRef(base) => write!(f, "&mut {base}"),
        }
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
            SignatureToken::Bool => TypeRef::Base(TypeTag::Bool),
            SignatureToken::U8 => TypeRef::Base(TypeTag::U8),
            SignatureToken::U16 => TypeRef::Base(TypeTag::U16),
            SignatureToken::U32 => TypeRef::Base(TypeTag::U32),
            SignatureToken::U64 => TypeRef::Base(TypeTag::U64),
            SignatureToken::U128 => TypeRef::Base(TypeTag::U128),
            SignatureToken::U256 => TypeRef::Base(TypeTag::U256),
            SignatureToken::Address => TypeRef::Base(TypeTag::Address),
            SignatureToken::Signer => TypeRef::Base(TypeTag::Signer),
            SignatureToken::Vector(element) => {
                let element_tag = match self.convert_signature_token(module, element) {
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
                let handle = module.struct_handle_at(*idx);
                let ident = DatatypeIdent::from_struct_handle(module, handle);

                // first try to see if this is an intrinsic type
                match IntrinsicType::try_parse_ident(&ident) {
                    Some(IntrinsicType::Bitvec) => TypeRef::Base(TypeTag::Bitvec),
                    Some(IntrinsicType::String) => TypeRef::Base(TypeTag::String),
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
                        TypeRef::Base(TypeTag::Datatype {
                            ident,
                            type_args: vec![],
                        })
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
                    None => {
                        // not an intrinsic type, locate the datatype
                        let decl = self
                            .decls
                            .get(&ident)
                            .unwrap_or_else(|| panic!("unregistered datatype {ident}"));
                        assert_eq!(decl.generics.len(), ty_args.len());
                        TypeRef::Base(TypeTag::Datatype {
                            ident,
                            type_args: ty_args,
                        })
                    },
                }
            },
            SignatureToken::Reference(inner) => {
                let inner_tag = match self.convert_signature_token(module, inner) {
                    TypeRef::Base(tag) => tag,
                    TypeRef::ImmRef(_) | TypeRef::MutRef(_) => {
                        panic!("reference type behind immutable borrow is not expected");
                    },
                };
                TypeRef::ImmRef(inner_tag)
            },
            SignatureToken::MutableReference(inner) => {
                let inner_tag = match self.convert_signature_token(module, inner) {
                    TypeRef::Base(tag) => tag,
                    TypeRef::ImmRef(_) | TypeRef::MutRef(_) => {
                        panic!("reference type behind mutable borrow is not expected");
                    },
                };
                TypeRef::MutRef(inner_tag)
            },
            SignatureToken::TypeParameter(idx) => TypeRef::Base(TypeTag::Param(*idx as usize)),
        }
    }

    /// Find all type bases that match the ability requirement
    ///
    /// - depth == 0 is the recursion termination condition
    /// - depth == 1 means do not instantiate any generic types, (e.g., `S<T>` will be ruled out)
    /// - depth == 2 means instantiate it at max once (e.g., `S<u64>`, `S<R>`, etc.)
    /// - depth == 3 means instantiate it at max twice (e.g., `S<S<u64>>`, `S<S<R>>`, etc.)
    pub fn type_bases_by_ability_constraint(
        &self,
        constraint: AbilitySet,
        depth: usize,
    ) -> Vec<TypeBase> {
        // recursion termination condition
        if depth == 0 {
            return vec![];
        }

        let mut result = vec![];

        // primitives
        if constraint.is_subset(AbilitySet::PRIMITIVES) {
            result.push(TypeBase::Bool);
            result.push(TypeBase::U8);
            result.push(TypeBase::U16);
            result.push(TypeBase::U32);
            result.push(TypeBase::U64);
            result.push(TypeBase::U128);
            result.push(TypeBase::U256);
            result.push(TypeBase::Bitvec);
            result.push(TypeBase::String);
            result.push(TypeBase::Address);
        }
        if constraint.is_subset(AbilitySet::SIGNER) {
            result.push(TypeBase::Signer);
        }

        // collections
        for variant in VECTOR_VARIANTS {
            let variant_abilities = variant.abilities();
            if !constraint.is_subset(variant_abilities) {
                continue;
            }

            // derive the baseline constraint for type instantiations
            let required_constraint = constraint.requires();
            let element_constraint = required_constraint.union(variant.type_param_element());
            for inst in self.type_bases_by_ability_constraint(element_constraint, depth - 1) {
                result.push(TypeBase::Vector {
                    element: inst.into(),
                    variant: variant.clone(),
                });
            }
        }
        for variant in MAP_VARIANTS {
            let variant_abilities = variant.abilities();
            if !constraint.is_subset(variant_abilities) {
                continue;
            }

            // derive the baseline constraint for type instantiations
            let required_constraint = constraint.requires();
            let key_constraint = required_constraint.union(variant.type_param_key());
            let key_insts = self.type_bases_by_ability_constraint(key_constraint, depth - 1);
            if key_insts.is_empty() {
                continue;
            }

            let value_constraint = required_constraint.union(variant.type_param_value());
            let value_insts = self.type_bases_by_ability_constraint(value_constraint, depth - 1);

            for ty_key in &key_insts {
                for ty_value in &value_insts {
                    result.push(TypeBase::Map {
                        key: ty_key.clone().into(),
                        value: ty_value.clone().into(),
                        variant: variant.clone(),
                    })
                }
            }
        }

        // datatypes
        for decl in self.decls.values() {
            // short-circuit if the constraint is not met
            if !constraint.is_subset(decl.abilities) {
                continue;
            }

            // no need to instantiate
            if decl.generics.is_empty() {
                result.push(TypeBase::Datatype {
                    ident: decl.ident.clone(),
                    type_args: vec![],
                    abilities: decl.abilities.clone(),
                });
                continue;
            }

            // derive the baseline constraint for type instantiations
            let required_constraint = constraint.requires();

            // instantiate the type arguments
            let mut ty_args_combo = vec![];
            for (requirement, is_phantom) in &decl.generics {
                let param_constraint = if *is_phantom {
                    *requirement
                } else {
                    required_constraint.union(*requirement)
                };
                let ty_args = self.type_bases_by_ability_constraint(param_constraint, depth - 1);
                ty_args_combo.push(ty_args);
            }

            for inst in ty_args_combo.iter().multi_cartesian_product() {
                let ty_args: Vec<_> = inst.into_iter().cloned().collect();
                let actual_abilities = derive_actual_ability(decl, &ty_args);
                result.push(TypeBase::Datatype {
                    ident: decl.ident.clone(),
                    type_args: ty_args,
                    abilities: actual_abilities,
                });
            }
        }

        // done
        result
    }

    /// Instantiate type parameters in this type tag with the type arguments
    pub fn instantiate_type_tag(&self, tag: &TypeTag, ty_args: &[TypeBase]) -> TypeBase {
        match tag {
            TypeTag::Bool => TypeBase::Bool,
            TypeTag::U8 => TypeBase::U8,
            TypeTag::U16 => TypeBase::U16,
            TypeTag::U32 => TypeBase::U32,
            TypeTag::U64 => TypeBase::U64,
            TypeTag::U128 => TypeBase::U128,
            TypeTag::U256 => TypeBase::U256,
            TypeTag::Bitvec => TypeBase::Bitvec,
            TypeTag::String => TypeBase::String,
            TypeTag::Address => TypeBase::Address,
            TypeTag::Signer => TypeBase::Signer,
            TypeTag::Vector { element, variant } => TypeBase::Vector {
                element: self.instantiate_type_tag(element, ty_args).into(),
                variant: variant.clone(),
            },
            TypeTag::Map {
                key,
                value,
                variant,
            } => TypeBase::Map {
                key: self.instantiate_type_tag(key, ty_args).into(),
                value: self.instantiate_type_tag(value, ty_args).into(),
                variant: variant.clone(),
            },
            TypeTag::Datatype { ident, type_args } => {
                let decl = self.decls.get(ident).expect("valid datatype ident only");
                debug_assert_eq!(type_args.len(), decl.generics.len());

                if type_args.is_empty() {
                    TypeBase::Datatype {
                        ident: ident.clone(),
                        type_args: vec![],
                        abilities: decl.abilities.clone(),
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
