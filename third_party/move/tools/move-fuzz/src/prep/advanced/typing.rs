// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

/// A type instance with concrete execution semantics
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
    Option {
        element: Box<Self>,
    },
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
    Object {
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
            | Self::Object { .. } => AbilitySet::PRIMITIVES,
            Self::Signer => AbilitySet::SIGNER,
            Self::Option { element } => {
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
            Self::Option { element } => write!(f, "std::option::Option<{element}>"),
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
            Self::Object {
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

/// Type unifier
pub struct TypeUnifier<'a> {
    generics: &'a [AbilitySet],
    unified: Vec<Option<TypeBase>>,
}

impl<'a> TypeUnifier<'a> {
    /// Initialize a type unification context
    pub fn new(generics: &'a [AbilitySet]) -> Self {
        Self {
            generics,
            unified: vec![None; generics.len()],
        }
    }

    fn check_or_unify_param(&mut self, param: usize, ty: TypeBase) -> bool {
        assert!(param < self.generics.len());
        if !ty.abilities().is_subset(self.generics[param]) {
            return false;
        }
        match self.unified.get(param).unwrap() {
            None => {
                self.unified.insert(param, Some(ty));
                true
            },
            Some(existing) => existing == &ty,
        }
    }

    /// Try to unify a type tag and a type base
    pub fn unify(&mut self, ty_tag: &TypeTag, ty_base: &TypeBase) -> bool {
        match (ty_tag, ty_base) {
            (TypeTag::Bool, TypeBase::Bool)
            | (TypeTag::U8, TypeBase::U8)
            | (TypeTag::U16, TypeBase::U16)
            | (TypeTag::U32, TypeBase::U32)
            | (TypeTag::U64, TypeBase::U64)
            | (TypeTag::U128, TypeBase::U128)
            | (TypeTag::U256, TypeBase::U256)
            | (TypeTag::Bitvec, TypeBase::Bitvec)
            | (TypeTag::String, TypeBase::String)
            | (TypeTag::Address, TypeBase::Address)
            | (TypeTag::Signer, TypeBase::Signer) => true,
            (
                TypeTag::Vector {
                    element: element_tag,
                    variant: variant_tag,
                },
                TypeBase::Vector {
                    element: element_base,
                    variant: variant_base,
                },
            ) => {
                if variant_tag != variant_base {
                    return false;
                }
                self.unify(element_tag, element_base)
            },
            (
                TypeTag::Map {
                    key: key_tag,
                    value: value_tag,
                    variant: variant_tag,
                },
                TypeBase::Map {
                    key: key_base,
                    value: value_base,
                    variant: variant_base,
                },
            ) => {
                if variant_tag != variant_base {
                    return false;
                }
                self.unify(key_tag, key_base) && self.unify(value_tag, value_base)
            },
            (
                TypeTag::Datatype {
                    ident: ident_tag,
                    type_args: type_args_tag,
                },
                TypeBase::Datatype {
                    ident: ident_base,
                    type_args: type_args_base,
                    abilities: _,
                },
            )
            | (
                TypeTag::ObjectKnown {
                    ident: ident_tag,
                    type_args: type_args_tag,
                },
                TypeBase::Object {
                    ident: ident_base,
                    type_args: type_args_base,
                    abilities: _,
                },
            ) => {
                if ident_tag != ident_base {
                    return false;
                }
                assert_eq!(type_args_tag.len(), type_args_base.len());
                for (sub_tag, sub_base) in type_args_tag.iter().zip(type_args_base.iter()) {
                    if !self.unify(sub_tag, sub_base) {
                        return false;
                    }
                }
                true
            },
            (TypeTag::Param(param), _) => self.check_or_unify_param(*param, ty_base.clone()),
            (
                TypeTag::ObjectParam(param),
                TypeBase::Object {
                    ident,
                    type_args,
                    abilities,
                },
            ) => {
                let datatype_base = TypeBase::Datatype {
                    ident: ident.clone(),
                    type_args: type_args.clone(),
                    abilities: *abilities,
                };
                self.check_or_unify_param(*param, datatype_base)
            },
            _ => false,
        }
    }

    /// Try to unify a series of (type_tag, type_base) pairs
    pub fn unify_all(&mut self, ty_tags: &[TypeTag], ty_bases: &[TypeBase]) -> bool {
        assert_eq!(ty_tags.len(), ty_bases.len());
        for (ty_tag, ty_base) in ty_tags.iter().zip(ty_bases.iter()) {
            if !self.unify(ty_tag, ty_base) {
                return false;
            }
        }
        true
    }

    /// Finish and return the type unification result
    pub fn finish(self) -> Vec<Option<TypeBase>> {
        self.unified
    }
}

impl SomeThing {
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

        // container of type bases that satisfy the constraint
        let mut result = vec![];

        // primitives
        if constraint.is_subset(AbilitySet::PRIMITIVES) {
            result.push(TypeBase::Bool);
            result.push(TypeBase::U8);
            result.push(TypeBase::I8);
            result.push(TypeBase::U16);
            result.push(TypeBase::I16);
            result.push(TypeBase::U32);
            result.push(TypeBase::I32);
            result.push(TypeBase::U64);
            result.push(TypeBase::I64);
            result.push(TypeBase::U128);
            result.push(TypeBase::I128);
            result.push(TypeBase::U256);
            result.push(TypeBase::I256);
            result.push(TypeBase::Bitvec);
            result.push(TypeBase::String);
            result.push(TypeBase::Address);
        }
        if constraint.is_subset(AbilitySet::SIGNER) {
            result.push(TypeBase::Signer);
        }

        // optional
        if constraint.is_subset(AbilitySet::VECTOR) {
            // derive the baseline constraint for type instantiations
            let element_constraint = constraint.requires();
            for inst in self.type_bases_by_ability_constraint(element_constraint, depth - 1) {
                result.push(TypeBase::Option {
                    element: inst.into(),
                });
            }
        }

        // collections
        for variant in VECTOR_VARIANTS {
            if !constraint.is_subset(variant.abilities()) {
                continue;
            }

            // derive the baseline constraint for type instantiations
            let required_constraint = constraint.requires();
            let element_constraint = required_constraint.union(variant.type_param_element());
            for inst in self.type_bases_by_ability_constraint(element_constraint, depth - 1) {
                result.push(TypeBase::Vector {
                    element: inst.into(),
                    variant: *variant,
                });
            }
        }
        for variant in MAP_VARIANTS {
            if !constraint.is_subset(variant.abilities()) {
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
                        variant: *variant,
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
                    abilities: decl.abilities,
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

        // object
        if constraint.is_subset(AbilitySet::PRIMITIVES) {
            for item in
                self.type_bases_by_ability_constraint(AbilitySet::EMPTY | Ability::Key, depth - 1)
            {
                match item {
                    TypeBase::Datatype {
                        ident,
                        type_args,
                        abilities,
                    } => {
                        result.push(TypeBase::Object {
                            ident,
                            type_args,
                            abilities,
                        });
                    },
                    _ => panic!("the type argument of Object must be a datatype"),
                }
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
                debug_assert_eq!(type_args.len(), decl.generics.len());

                if type_args.is_empty() {
                    TypeBase::Object {
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
                    TypeBase::Object {
                        ident: ident.clone(),
                        type_args: ty_args,
                        abilities: actual_abilities,
                    }
                }
            },
            TypeTag::ObjectParam(index) => {
                match ty_args.get(*index).expect("type arguments in bound") {
                    TypeBase::Datatype {
                        ident,
                        type_args,
                        abilities,
                    } => TypeBase::Object {
                        ident: ident.clone(),
                        type_args: type_args.clone(),
                        abilities: *abilities,
                    },
                    _ => panic!("type argument for Object must be a datatype"),
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

/// Instantiation of a function
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct FunctionInst {
    pub ident: FunctionIdent,
    pub type_args: Vec<TypeBase>,
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
