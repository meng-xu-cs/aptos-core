use crate::fuzz::{
    entrypoint::{FunctionDecl, FunctionRegistry},
    ident::{DatatypeIdent, FunctionIdent},
    typing::{DatatypeRegistry, MapVariant, TypeBase, TypeItem, VectorVariant},
};
use itertools::Itertools;
use move_binary_format::file_format::AbilitySet;
use std::fmt::Display;

/// Instantiation of a function
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct FunctionInst {
    ident: FunctionIdent,
    type_args: Vec<TypeBase>,
}

impl Display for FunctionInst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.type_args.is_empty() {
            write!(f, "{}", self.ident)
        } else {
            let inst = self.type_args.iter().join(", ");
            write!(f, "{}<{inst}>", self.ident)
        }
    }
}

/// Types that can be trivially constructed and destructed
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum SimpleType {
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
    Object {
        ident: DatatypeIdent,
        type_args: Vec<TypeBase>,
        abilities: AbilitySet,
    },
}

impl From<SimpleType> for TypeBase {
    fn from(t: SimpleType) -> TypeBase {
        match t {
            SimpleType::Bool => TypeBase::Bool,
            SimpleType::U8 => TypeBase::U8,
            SimpleType::U16 => TypeBase::U16,
            SimpleType::U32 => TypeBase::U32,
            SimpleType::U64 => TypeBase::U64,
            SimpleType::U128 => TypeBase::U128,
            SimpleType::U256 => TypeBase::U256,
            SimpleType::Bitvec => TypeBase::Bitvec,
            SimpleType::String => TypeBase::String,
            SimpleType::Address => TypeBase::Address,
            SimpleType::Signer => TypeBase::Signer,
            SimpleType::Vector { element, variant } => TypeBase::Vector {
                element: Box::new((*element).into()),
                variant,
            },
            SimpleType::Map {
                key,
                value,
                variant,
            } => TypeBase::Map {
                key: Box::new((*key).into()),
                value: Box::new((*value).into()),
                variant,
            },
            SimpleType::Object {
                ident,
                type_args,
                abilities,
            } => TypeBase::Object {
                ident,
                type_args,
                abilities,
            },
        }
    }
}

/// A type closure constructed based on datatypes (cannot be trivially handled)
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum ComplexType {
    Unit {
        ident: DatatypeIdent,
        type_args: Vec<TypeBase>,
        abilities: AbilitySet,
    },
    Vector {
        element: Box<Self>,
        variant: VectorVariant,
    },
    MapOnKey {
        key: Box<Self>,
        value: SimpleType,
        variant: MapVariant,
    },
    MapOnValue {
        key: SimpleType,
        value: Box<Self>,
        variant: MapVariant,
    },
    MapOnBoth {
        key: Box<Self>,
        value: Box<Self>,
        variant: MapVariant,
    },
}

impl From<ComplexType> for TypeBase {
    fn from(t: ComplexType) -> TypeBase {
        match t {
            ComplexType::Unit {
                ident,
                type_args,
                abilities,
            } => TypeBase::Datatype {
                ident,
                type_args,
                abilities,
            },
            ComplexType::Vector { element, variant } => TypeBase::Vector {
                element: Box::new((*element).into()),
                variant,
            },
            ComplexType::MapOnKey {
                key,
                value,
                variant,
            } => TypeBase::Map {
                key: Box::new((*key).into()),
                value: Box::new(value.into()),
                variant,
            },
            ComplexType::MapOnValue {
                key,
                value,
                variant,
            } => TypeBase::Map {
                key: Box::new(key.into()),
                value: Box::new((*value).into()),
                variant,
            },
            ComplexType::MapOnBoth {
                key,
                value,
                variant,
            } => TypeBase::Map {
                key: Box::new((*key).into()),
                value: Box::new((*value).into()),
                variant,
            },
        }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeClosureBase {
    Simple(SimpleType),
    Complex(ComplexType),
}

impl From<TypeBase> for TypeClosureBase {
    fn from(t: TypeBase) -> TypeClosureBase {
        match t {
            TypeBase::Bool => TypeClosureBase::Simple(SimpleType::Bool),
            TypeBase::U8 => TypeClosureBase::Simple(SimpleType::U8),
            TypeBase::U16 => TypeClosureBase::Simple(SimpleType::U16),
            TypeBase::U32 => TypeClosureBase::Simple(SimpleType::U32),
            TypeBase::U64 => TypeClosureBase::Simple(SimpleType::U64),
            TypeBase::U128 => TypeClosureBase::Simple(SimpleType::U128),
            TypeBase::U256 => TypeClosureBase::Simple(SimpleType::U256),
            TypeBase::Bitvec => TypeClosureBase::Simple(SimpleType::Bitvec),
            TypeBase::String => TypeClosureBase::Simple(SimpleType::String),
            TypeBase::Address => TypeClosureBase::Simple(SimpleType::Address),
            TypeBase::Signer => TypeClosureBase::Simple(SimpleType::Signer),
            TypeBase::Vector { element, variant } => match TypeClosureBase::from(*element) {
                TypeClosureBase::Simple(simple_element) => {
                    TypeClosureBase::Simple(SimpleType::Vector {
                        element: simple_element.into(),
                        variant,
                    })
                },
                TypeClosureBase::Complex(complex_element) => {
                    TypeClosureBase::Complex(ComplexType::Vector {
                        element: complex_element.into(),
                        variant,
                    })
                },
            },
            TypeBase::Map {
                key,
                value,
                variant,
            } => match (TypeClosureBase::from(*key), TypeClosureBase::from(*value)) {
                (TypeClosureBase::Simple(simple_key), TypeClosureBase::Simple(simple_value)) => {
                    TypeClosureBase::Simple(SimpleType::Map {
                        key: simple_key.into(),
                        value: simple_value.into(),
                        variant,
                    })
                },
                (TypeClosureBase::Simple(simple_key), TypeClosureBase::Complex(complex_value)) => {
                    TypeClosureBase::Complex(ComplexType::MapOnValue {
                        key: simple_key,
                        value: complex_value.into(),
                        variant,
                    })
                },
                (TypeClosureBase::Complex(complex_key), TypeClosureBase::Simple(simple_value)) => {
                    TypeClosureBase::Complex(ComplexType::MapOnKey {
                        key: complex_key.into(),
                        value: simple_value,
                        variant,
                    })
                },
                (
                    TypeClosureBase::Complex(complex_key),
                    TypeClosureBase::Complex(complex_value),
                ) => TypeClosureBase::Complex(ComplexType::MapOnBoth {
                    key: complex_key.into(),
                    value: complex_value.into(),
                    variant,
                }),
            },
            TypeBase::Datatype {
                ident,
                type_args,
                abilities,
            } => TypeClosureBase::Complex(ComplexType::Unit {
                ident,
                type_args,
                abilities,
            }),
            TypeBase::Object {
                ident,
                type_args,
                abilities,
            } => TypeClosureBase::Simple(SimpleType::Object {
                ident,
                type_args,
                abilities,
            }),
        }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeClosureItem {
    Base(TypeClosureBase),
    ImmRef(TypeClosureBase),
    MutRef(TypeClosureBase),
}

impl From<TypeItem> for TypeClosureItem {
    fn from(t: TypeItem) -> TypeClosureItem {
        match t {
            TypeItem::Base(base) => TypeClosureItem::Base(base.into()),
            TypeItem::ImmRef(base) => TypeClosureItem::ImmRef(base.into()),
            TypeItem::MutRef(base) => TypeClosureItem::MutRef(base.into()),
        }
    }
}

/// A driver generator that also caches information during driver generation
pub struct DriverGenerator<'a> {
    datatype_registry: &'a DatatypeRegistry,
    function_registry: &'a FunctionRegistry,
    type_recursion_depth: usize,
}

impl<'a> DriverGenerator<'a> {
    /// Create a new generator with necessary information
    pub fn new(
        datatype_registry: &'a DatatypeRegistry,
        function_registry: &'a FunctionRegistry,
        type_recursion_depth: usize,
    ) -> Self {
        Self {
            datatype_registry,
            function_registry,
            type_recursion_depth,
        }
    }

    /// Collect possible function instantiations
    fn collect_function_insts(&self, decl: &FunctionDecl) -> Vec<FunctionInst> {
        let mut result = vec![];

        // shortcut when this function is not a generic function
        if decl.generics.is_empty() {
            result.push(FunctionInst {
                ident: decl.ident.clone(),
                type_args: vec![],
            });
            return result;
        }

        // instantiate each of the required type argument
        let mut ty_args_combo = vec![];
        for constraint in &decl.generics {
            let ty_args = self
                .datatype_registry
                .type_bases_by_ability_constraint(*constraint, self.type_recursion_depth);
            ty_args_combo.push(ty_args);
        }

        for inst in ty_args_combo.iter().multi_cartesian_product() {
            result.push(FunctionInst {
                ident: decl.ident.clone(),
                type_args: inst.into_iter().cloned().collect(),
            });
        }

        // done with the collection
        result
    }

    /// Generate drivers (zero to multiple) for an entrypoint instance
    fn generate_drivers_for_inst(&mut self, decl: &FunctionDecl, inst: &FunctionInst) {
        debug_assert_eq!(decl.ident, inst.ident);
        log::debug!("deriving script for {inst}");

        // further instantiate parameter and return types
        let params: Vec<_> = decl
            .parameters
            .iter()
            .map(|t| {
                TypeClosureItem::from(
                    self.datatype_registry
                        .instantiate_type_ref(t, &inst.type_args),
                )
            })
            .collect();
        let ret_ty: Vec<_> = decl
            .return_sig
            .iter()
            .map(|t| {
                TypeClosureItem::from(
                    self.datatype_registry
                        .instantiate_type_ref(t, &inst.type_args),
                )
            })
            .collect();
    }

    /// Generate drivers (zero to multiple) for an entrypoint declaration
    pub fn generate_drivers_for_decl(&mut self, decl: &FunctionDecl) {
        // derive instantiations
        for inst in self.collect_function_insts(decl) {
            self.generate_drivers_for_inst(decl, &inst);
        }
    }
}
