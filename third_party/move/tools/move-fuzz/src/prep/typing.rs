// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::prep::ident::DatatypeIdent;
use itertools::Itertools;
use move_core_types::{ability::AbilitySet, account_address::AccountAddress};
use std::fmt::Display;

/// Intrinsic datatypes known and specially handled
pub enum IntrinsicType {
    Bitvec,
    String,
    Object,
}

impl IntrinsicType {
    pub fn try_parse_ident(ident: &DatatypeIdent) -> Option<Self> {
        if ident.address() != AccountAddress::ONE {
            return None;
        }
        let parsed = match (ident.module_name(), ident.datatype_name()) {
            ("bit_vector", "BitVector") => IntrinsicType::Bitvec,
            ("string", "String") => IntrinsicType::String,
            ("object", "Object") => IntrinsicType::Object,
            _ => return None,
        };
        Some(parsed)
    }
}

/// A specific type instance within a typing context
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeTag {
    Bool,
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    U128,
    I128,
    U256,
    I256,
    Bitvec,
    String,
    Address,
    Signer,
    Vector {
        element: Box<Self>,
    },
    Datatype {
        ident: DatatypeIdent,
        type_args: Vec<Self>,
    },
    Param(usize),
    ObjectKnown {
        ident: DatatypeIdent,
        type_args: Vec<Self>,
    },
    ObjectParam(usize),
}

impl Display for TypeTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool => write!(f, "bool"),
            Self::U8 => write!(f, "u8"),
            Self::I8 => write!(f, "i8"),
            Self::U16 => write!(f, "u16"),
            Self::I16 => write!(f, "i16"),
            Self::U32 => write!(f, "u32"),
            Self::I32 => write!(f, "i32"),
            Self::U64 => write!(f, "u64"),
            Self::I64 => write!(f, "i64"),
            Self::U128 => write!(f, "u128"),
            Self::I128 => write!(f, "i128"),
            Self::U256 => write!(f, "u256"),
            Self::I256 => write!(f, "i256"),
            Self::Bitvec => write!(f, "std::bit_vector::BitVector"),
            Self::String => write!(f, "std::string::String"),
            Self::Address => write!(f, "address"),
            Self::Signer => write!(f, "signer"),
            Self::Vector { element } => write!(f, "vector<{element}>"),
            Self::Datatype { ident, type_args } => {
                if type_args.is_empty() {
                    write!(f, "{ident}")
                } else {
                    let inst = type_args.iter().join(", ");
                    write!(f, "{ident}<{inst}>")
                }
            },
            Self::Param(index) => write!(f, "#{index}"),
            Self::ObjectKnown { ident, type_args } => {
                if type_args.is_empty() {
                    write!(f, "aptos_framework::object::Object<{ident}>")
                } else {
                    let inst = type_args.iter().join(", ");
                    write!(f, "aptos_framework::object::Object<{ident}<{inst}>>")
                }
            },
            Self::ObjectParam(index) => write!(f, "aptos_framework::object::Object<#{index}>"),
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

/// A type instance with concrete execution semantics
///
/// This enum is intentionally kept in-sync with `TypeTag`,
/// with the addition of `abilities` information for datatypes and generics.
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeBase {
    Bool,
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    U128,
    I128,
    U256,
    I256,
    Bitvec,
    String,
    Address,
    Signer,
    Vector {
        element: Box<Self>,
    },
    Datatype {
        ident: DatatypeIdent,
        type_args: Vec<Self>,
        abilities: AbilitySet,
    },
    Param {
        index: usize,
        abilities: AbilitySet,
    },
    ObjectKnown {
        ident: DatatypeIdent,
        type_args: Vec<Self>,
        abilities: AbilitySet,
    },
    ObjectParam {
        index: usize,
        abilities: AbilitySet,
    },
}

impl TypeBase {
    /// Retrieve the abilities of this type base
    pub fn abilities(&self) -> AbilitySet {
        match self {
            Self::Bool
            | Self::U8
            | Self::I8
            | Self::U16
            | Self::I16
            | Self::U32
            | Self::I32
            | Self::U64
            | Self::I64
            | Self::U128
            | Self::I128
            | Self::U256
            | Self::I256
            | Self::Bitvec
            | Self::String
            | Self::Address
            | Self::ObjectKnown { .. }
            | Self::ObjectParam { .. } => AbilitySet::PRIMITIVES,
            Self::Signer => AbilitySet::SIGNER,
            Self::Vector { element } => {
                let mut actual_abilities = AbilitySet::EMPTY;
                let provided_abilities = element.abilities();
                for ability in AbilitySet::VECTOR {
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
            Self::Param {
                index: _,
                abilities,
            } => *abilities,
        }
    }
}

impl Display for TypeBase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bool => write!(f, "bool"),
            Self::U8 => write!(f, "u8"),
            Self::I8 => write!(f, "i8"),
            Self::U16 => write!(f, "u16"),
            Self::I16 => write!(f, "i16"),
            Self::U32 => write!(f, "u32"),
            Self::I32 => write!(f, "i32"),
            Self::U64 => write!(f, "u64"),
            Self::I64 => write!(f, "i64"),
            Self::U128 => write!(f, "u128"),
            Self::I128 => write!(f, "i128"),
            Self::U256 => write!(f, "u256"),
            Self::I256 => write!(f, "i256"),
            Self::Bitvec => write!(f, "std::bit_vector::BitVector"),
            Self::String => write!(f, "std::string::String"),
            Self::Address => write!(f, "address"),
            Self::Signer => write!(f, "signer"),
            Self::Vector { element } => write!(f, "vector<{element}>"),
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
            Self::Param {
                index,
                abilities: _,
            } => write!(f, "#{index}"),
            Self::ObjectKnown {
                ident,
                type_args,
                abilities: _,
            } => {
                if type_args.is_empty() {
                    write!(f, "aptos_framework::object::Object<{ident}>")
                } else {
                    let inst = type_args.iter().join(", ");
                    write!(f, "aptos_framework::object::Object<{ident}<{inst}>>")
                }
            },
            Self::ObjectParam {
                index,
                abilities: _,
            } => write!(f, "aptos_framework::object::Object<#{index}>"),
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

impl TypeItem {
    /// Retrieve the abilities of this type base
    pub fn abilities(&self) -> AbilitySet {
        match self {
            Self::Base(base) => base.abilities(),
            Self::ImmRef(_) | Self::MutRef(_) => AbilitySet::REFERENCES,
        }
    }
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

/// Types that can be trivially constructed and destructed
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum SimpleType {
    Bool,
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    U128,
    I128,
    U256,
    I256,
    Bitvec,
    String,
    Address,
    Signer,
    Vector {
        element: Box<Self>,
    },
    ObjectKnown {
        ident: DatatypeIdent,
        type_args: Vec<TypeBase>,
        abilities: AbilitySet,
    },
    ObjectParam {
        index: usize,
        abilities: AbilitySet,
    },
}

impl SimpleType {
    /// Revert it back to a `TypeBase`
    pub fn revert(&self) -> TypeBase {
        match self {
            Self::Bool => TypeBase::Bool,
            Self::U8 => TypeBase::U8,
            Self::I8 => TypeBase::I8,
            Self::U16 => TypeBase::U16,
            Self::I16 => TypeBase::I16,
            Self::U32 => TypeBase::U32,
            Self::I32 => TypeBase::I32,
            Self::U64 => TypeBase::U64,
            Self::I64 => TypeBase::I64,
            Self::U128 => TypeBase::U128,
            Self::I128 => TypeBase::I128,
            Self::U256 => TypeBase::U256,
            Self::I256 => TypeBase::I256,
            Self::Bitvec => TypeBase::Bitvec,
            Self::String => TypeBase::String,
            Self::Address => TypeBase::Address,
            Self::Signer => TypeBase::Signer,
            Self::Vector { element } => TypeBase::Vector {
                element: Box::new(element.revert()),
            },
            Self::ObjectKnown {
                ident,
                type_args,
                abilities,
            } => TypeBase::ObjectKnown {
                ident: ident.clone(),
                type_args: type_args.clone(),
                abilities: *abilities,
            },
            Self::ObjectParam { index, abilities } => TypeBase::ObjectParam {
                index: *index,
                abilities: *abilities,
            },
        }
    }
}

/// A type constructed based on datatypes or parameters (cannot be trivially handled)
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum ComplexType {
    Datatype {
        ident: DatatypeIdent,
        type_args: Vec<TypeBase>,
        abilities: AbilitySet,
    },
    Param {
        index: usize,
        abilities: AbilitySet,
    },
    Vector {
        element: Box<Self>,
    },
}

impl ComplexType {
    /// Revert it back to a `TypeBase`
    pub fn revert(&self) -> TypeBase {
        match self {
            Self::Datatype {
                ident,
                type_args,
                abilities,
            } => TypeBase::Datatype {
                ident: ident.clone(),
                type_args: type_args.clone(),
                abilities: *abilities,
            },
            Self::Param { index, abilities } => TypeBase::Param {
                index: *index,
                abilities: *abilities,
            },
            Self::Vector { element } => TypeBase::Vector {
                element: Box::new(element.revert()),
            },
        }
    }
}

/// Either a simple type or a complex type
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeMode {
    Simple(SimpleType),
    Complex(ComplexType),
}

impl TypeMode {
    /// Revert it back to a `TypeBase`
    pub fn revert(&self) -> TypeBase {
        match self {
            Self::Simple(simple) => simple.revert(),
            Self::Complex(complex) => complex.revert(),
        }
    }
}

impl TypeMode {
    /// Convert a type base into a type mode
    pub fn convert(t: &TypeBase) -> Self {
        match t {
            TypeBase::Bool => Self::Simple(SimpleType::Bool),
            TypeBase::U8 => Self::Simple(SimpleType::U8),
            TypeBase::I8 => Self::Simple(SimpleType::I8),
            TypeBase::U16 => Self::Simple(SimpleType::U16),
            TypeBase::I16 => Self::Simple(SimpleType::I16),
            TypeBase::U32 => Self::Simple(SimpleType::U32),
            TypeBase::I32 => Self::Simple(SimpleType::I32),
            TypeBase::U64 => Self::Simple(SimpleType::U64),
            TypeBase::I64 => Self::Simple(SimpleType::I64),
            TypeBase::U128 => Self::Simple(SimpleType::U128),
            TypeBase::I128 => Self::Simple(SimpleType::I128),
            TypeBase::U256 => Self::Simple(SimpleType::U256),
            TypeBase::I256 => Self::Simple(SimpleType::I256),
            TypeBase::Bitvec => Self::Simple(SimpleType::Bitvec),
            TypeBase::String => Self::Simple(SimpleType::String),
            TypeBase::Address => Self::Simple(SimpleType::Address),
            TypeBase::Signer => Self::Simple(SimpleType::Signer),
            TypeBase::Vector { element } => match Self::convert(element) {
                Self::Simple(elem_simple) => Self::Simple(SimpleType::Vector {
                    element: Box::new(elem_simple),
                }),
                Self::Complex(elem_complex) => Self::Complex(ComplexType::Vector {
                    element: Box::new(elem_complex),
                }),
            },
            TypeBase::Datatype {
                ident,
                type_args,
                abilities,
            } => Self::Complex(ComplexType::Datatype {
                ident: ident.clone(),
                type_args: type_args.clone(),
                abilities: *abilities,
            }),
            TypeBase::Param { index, abilities } => Self::Complex(ComplexType::Param {
                index: *index,
                abilities: *abilities,
            }),
            TypeBase::ObjectKnown {
                ident,
                type_args,
                abilities,
            } => Self::Simple(SimpleType::ObjectKnown {
                ident: ident.clone(),
                type_args: type_args.clone(),
                abilities: *abilities,
            }),
            TypeBase::ObjectParam { index, abilities } => Self::Simple(SimpleType::ObjectParam {
                index: *index,
                abilities: *abilities,
            }),
        }
    }
}
