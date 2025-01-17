use crate::fuzz::ident::{DatatypeIdent, ModuleIdent};
use move_binary_format::{access::ModuleAccess, file_format::AbilitySet, CompiledModule};
use move_core_types::account_address::AccountAddress;
use std::collections::BTreeMap;

/// The context in which `TypeTag` and `TypeRef` is defined
pub trait TypingContext {
    fn type_params(&self) -> &[AbilitySet];
}

/// A type parameter within a context
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct TypeParam<'a, T: TypingContext> {
    context: &'a T,
    index: usize,
}

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
pub enum TypeTag<'a, T: TypingContext> {
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
    Datatype(DatatypeInst<'a, T>),
    Param(TypeParam<'a, T>),
}

/// A type that can appear in function declarations
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeRef<'a, T: TypingContext> {
    Owned(TypeTag<'a, T>),
    ImmRef(TypeTag<'a, T>),
    MutRef(TypeTag<'a, T>),
}

/// Instantiation of a datatype
#[derive(Debug, Ord, PartialOrd, Eq, PartialEq)]
pub struct DatatypeInst<'a, T: TypingContext> {
    ident: DatatypeIdent,
    context: &'a T,
    type_args: Vec<TypeTag<'a, T>>,
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
        if ident.module.address != AccountAddress::ONE {
            return None;
        }
        let parsed = match (ident.module.name.as_str(), ident.datatype.as_str()) {
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
    ident: DatatypeIdent,
    abilities: AbilitySet,
    type_params: Vec<AbilitySet>,
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
    pub fn analyze(&mut self, module: &CompiledModule) {
        let module_ident = ModuleIdent {
            address: *module.address(),
            name: module.name().to_owned(),
        };

        // go over all structs defined
        for struct_def in &module.struct_defs {
            let struct_handle = module.struct_handle_at(struct_def.struct_handle);
            let datatype_ident = DatatypeIdent {
                module: module_ident.clone(),
                datatype: module.identifier_at(struct_handle.name).to_owned(),
            };

            // skip intrinsic types
            if IntrinsicType::try_parse_ident(&datatype_ident).is_some() {
                continue;
            }

            // add the declaration
            let decl = DatatypeDecl {
                ident: datatype_ident.clone(),
                abilities: struct_handle.abilities,
                type_params: struct_handle
                    .type_parameters
                    .iter()
                    .map(|p| p.constraints)
                    .collect(),
            };
            let existing = self.decls.insert(datatype_ident, decl);
            assert!(existing.is_none());
        }
    }
}
