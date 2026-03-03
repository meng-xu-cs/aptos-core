// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::{
    account::{AddressKind, NamedAddressKind},
    executor::tracing::ResourceWrite,
    prep::{canvas::BasicInput, ident::DatatypeIdent},
};
use move_core_types::{
    ability::AbilitySet,
    account_address::AccountAddress,
    int256::{I256, U256},
    language_storage::TypeTag as VmTypeTag,
    value::MoveValue,
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::{BTreeMap, BTreeSet};

// Probabilities and configurations
const GEN_PROB: u8 = 50;
const MUT_PROB: u8 = 50;
const TOTAL_PROB: u8 = GEN_PROB + MUT_PROB;

const GEN_INT_PROB_MIN: u8 = 10;
const GEN_INT_PROB_MAX: u8 = 10;
const GEN_INT_PROB_ANY: u8 = 80;
const GEN_INT_PROB_TOTAL: u8 = GEN_INT_PROB_MIN + GEN_INT_PROB_MAX + GEN_INT_PROB_ANY;

const MUT_INT_PROB_ADD_1: u8 = 20;
const MUT_INT_PROB_SUB_1: u8 = 20;
const MUT_INT_PROB_MUL_2: u8 = 20;
const MUT_INT_PROB_DIV_2: u8 = 20;
const MUT_INT_PROB_FLIP_BITS: u8 = 20;
const MUT_INT_PROB_TOTAL: u8 = MUT_INT_PROB_ADD_1
    + MUT_INT_PROB_SUB_1
    + MUT_INT_PROB_MUL_2
    + MUT_INT_PROB_DIV_2
    + MUT_INT_PROB_FLIP_BITS;

const GEN_VEC_SIZE_MAX: u8 = 8;

const MUT_VEC_PROB_ADD_ELEMENT: u8 = 30;
const MUT_VEC_PROB_DEL_ELEMENT: u8 = 30;
const MUT_VEC_PROB_MUT_ELEMENT: u8 = 40;
const MUT_VEC_PROB_TOTAL: u8 =
    MUT_VEC_PROB_ADD_ELEMENT + MUT_VEC_PROB_DEL_ELEMENT + MUT_VEC_PROB_MUT_ELEMENT;

const GEN_ADDR_PROB_NAME_PRIMARY: u8 = 40;
const GEN_ADDR_PROB_NAME_DEPENDENCY: u8 = 10;
const GEN_ADDR_PROB_NAME_FRAMEWORK: u8 = 5;
const GEN_ADDR_PROB_USER: u8 = 45;
const GEN_ADDR_PROB_TOTAL: u8 = GEN_ADDR_PROB_NAME_PRIMARY
    + GEN_ADDR_PROB_NAME_DEPENDENCY
    + GEN_ADDR_PROB_NAME_FRAMEWORK
    + GEN_ADDR_PROB_USER;

const GEN_STR_MAX_LEN: usize = 32;

const GEN_STR_PROB_DICT: u8 = 30;
const GEN_STR_PROB_EMPTY: u8 = 20;
const GEN_STR_PROB_RANDOM: u8 = 50;
const GEN_STR_PROB_TOTAL: u8 = GEN_STR_PROB_DICT + GEN_STR_PROB_EMPTY + GEN_STR_PROB_RANDOM;

const MUT_STR_PROB_ADD: u8 = 25;
const MUT_STR_PROB_DEL: u8 = 25;
const MUT_STR_PROB_CHANGE: u8 = 25;
const MUT_STR_PROB_DICT: u8 = 25;
const MUT_STR_PROB_TOTAL: u8 =
    MUT_STR_PROB_ADD + MUT_STR_PROB_DEL + MUT_STR_PROB_CHANGE + MUT_STR_PROB_DICT;

const DEFAULT_STRING_DICTIONARY: &[&str] = &[
    "",
    "test",
    "hello",
    "admin",
    "user",
    "token",
    "pool",
    "coin",
    "apt",
    "usdc",
    "usdt",
    "btc",
    "eth",
    "0",
    "1",
    "true",
    "false",
    "name",
    "symbol",
    "description",
    "uri",
    "metadata",
];

const MUT_TYPE_ARG_PROB: u8 = 30;

macro_rules! create_int {
    ($s:expr, $t:ty) => {{
        let x = $s.rng.gen_range(0, GEN_INT_PROB_TOTAL);
        if x < GEN_INT_PROB_MIN {
            <$t>::MIN
        } else if x >= GEN_INT_PROB_MAX {
            <$t>::MAX
        } else {
            $s.rng.r#gen()
        }
    }};
    ($s:expr, $min:expr, $max:expr, $rand:expr) => {{
        let x = $s.rng.gen_range(0, GEN_INT_PROB_TOTAL);
        if x < GEN_INT_PROB_MIN {
            $min
        } else if x >= GEN_INT_PROB_MAX {
            $max
        } else {
            $rand
        }
    }};
}

macro_rules! mutate_int {
    ($s:expr, $v:expr) => {{
        let x = $s.rng.gen_range(0, MUT_INT_PROB_TOTAL);
        if x < MUT_INT_PROB_ADD_1 {
            $v.wrapping_add(1)
        } else if x < MUT_INT_PROB_ADD_1 + MUT_INT_PROB_SUB_1 {
            $v.wrapping_sub(1)
        } else if x < MUT_INT_PROB_ADD_1 + MUT_INT_PROB_SUB_1 + MUT_INT_PROB_MUL_2 {
            $v.wrapping_mul(2)
        } else if x < MUT_INT_PROB_ADD_1
            + MUT_INT_PROB_SUB_1
            + MUT_INT_PROB_MUL_2
            + MUT_INT_PROB_DIV_2
        {
            $v.wrapping_div(2)
        } else {
            !$v
        }
    }};
}

macro_rules! mutate_int256 {
    ($s:expr, $t:ty, $v:expr) => {{
        let x = $s.rng.gen_range(0, MUT_INT_PROB_TOTAL);
        if x < MUT_INT_PROB_ADD_1 {
            <$t>::checked_add($v, <$t>::from(1u8)).unwrap_or(<$t>::ZERO)
        } else if x < MUT_INT_PROB_ADD_1 + MUT_INT_PROB_SUB_1 {
            <$t>::checked_sub($v, <$t>::from(1u8)).unwrap_or(<$t>::ZERO)
        } else if x < MUT_INT_PROB_ADD_1 + MUT_INT_PROB_SUB_1 + MUT_INT_PROB_MUL_2 {
            <$t>::checked_mul($v, <$t>::from(2u8)).unwrap_or(<$t>::ZERO)
        } else if x < MUT_INT_PROB_ADD_1
            + MUT_INT_PROB_SUB_1
            + MUT_INT_PROB_MUL_2
            + MUT_INT_PROB_DIV_2
        {
            <$t>::checked_div($v, <$t>::from(2u8)).unwrap_or(<$t>::ZERO)
        } else {
            <$t>::ZERO
        }
    }};
}

/// A pool of concrete VM TypeTag values indexed by their AbilitySet
#[derive(Clone)]
pub struct TypePool {
    /// All types in the pool, each paired with its abilities
    entries: Vec<(VmTypeTag, AbilitySet)>,
}

impl TypePool {
    /// Create a new empty type pool
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Add a type with its abilities to the pool
    pub fn add(&mut self, ty: VmTypeTag, abilities: AbilitySet) {
        self.entries.push((ty, abilities));
    }

    /// Return all types whose abilities are a superset of the given constraint
    pub fn candidates_for(&self, constraint: AbilitySet) -> Vec<&VmTypeTag> {
        self.entries
            .iter()
            .filter(|(_, abilities)| constraint.is_subset(*abilities))
            .map(|(ty, _)| ty)
            .collect()
    }
}

/// Input generator and mutator
pub struct Mutator {
    // random number generator
    rng: StdRng,

    // dictionaries
    dict_address: BTreeMap<AddressKind, BTreeSet<AccountAddress>>,
    dict_string: Vec<String>,

    // type pool for generic type argument generation
    type_pool: TypePool,

    // object tracking: addresses confirmed as objects (have ObjectGroup)
    object_addresses: BTreeSet<AccountAddress>,

    // resource type -> set of object addresses where that resource exists
    // keyed by DatatypeIdent only (ignoring type_args) because converting
    // runtime VmTypeTag to TypeBase requires ability information that is
    // unavailable from write sets. matching by ident alone is sufficient
    // for fuzzing: a mismatched type arg just triggers an abort, which is
    // strictly better than the previous AccountAddress::ZERO.
    dict_object: BTreeMap<DatatypeIdent, BTreeSet<AccountAddress>>,
}

impl Mutator {
    /// Create a new random mutator
    pub fn new(
        seed: u64,
        dict_address: BTreeMap<AddressKind, BTreeSet<AccountAddress>>,
        type_pool: TypePool,
        dict_string: Vec<String>,
    ) -> Mutator {
        let dict_string = if dict_string.is_empty() {
            DEFAULT_STRING_DICTIONARY
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            dict_string
        };
        Self {
            rng: StdRng::seed_from_u64(seed),
            dict_address,
            dict_string,
            type_pool,
            object_addresses: BTreeSet::new(),
            dict_object: BTreeMap::new(),
        }
    }

    /// Decide whether to generate a new value or mutate an existing one
    pub fn should_mutate(&mut self, num_seeds: usize) -> Option<usize> {
        if num_seeds == 0 {
            return None;
        }

        let x = self.rng.gen_range(0, TOTAL_PROB);
        if x < GEN_PROB {
            return None;
        }

        let index = self.rng.gen_range(0, num_seeds);
        Some(index)
    }

    /// Randomly generate a Move value based on a basic input type
    pub fn random_value(&mut self, ty: &BasicInput) -> MoveValue {
        match ty {
            BasicInput::Bool => MoveValue::Bool(self.rng.r#gen()),
            BasicInput::U8 => MoveValue::U8(create_int!(self, u8)),
            BasicInput::I8 => MoveValue::I8(create_int!(self, i8)),
            BasicInput::U16 => MoveValue::U16(create_int!(self, u16)),
            BasicInput::I16 => MoveValue::I16(create_int!(self, i16)),
            BasicInput::U32 => MoveValue::U32(create_int!(self, u32)),
            BasicInput::I32 => MoveValue::I32(create_int!(self, i32)),
            BasicInput::U64 => MoveValue::U64(create_int!(self, u64)),
            BasicInput::I64 => MoveValue::I64(create_int!(self, i64)),
            BasicInput::U128 => MoveValue::U128(create_int!(self, u128)),
            BasicInput::I128 => MoveValue::I128(create_int!(self, i128)),
            BasicInput::U256 => MoveValue::U256(create_int!(
                self,
                U256::ZERO,
                U256::MAX,
                U256::from_le_bytes(self.rng.r#gen())
            )),
            BasicInput::I256 => MoveValue::I256(create_int!(
                self,
                I256::MIN,
                I256::MAX,
                I256::from_le_bytes(self.rng.r#gen())
            )),
            BasicInput::String => self.random_string(),
            BasicInput::Address => MoveValue::Address(self.random_address()),
            BasicInput::Signer => MoveValue::Signer(self.random_signer()),
            BasicInput::ObjectKnown { ident, .. } => {
                MoveValue::Address(self.random_object_address_for(ident))
            },
            BasicInput::ObjectParam { .. } => MoveValue::Address(self.random_object_address_any()),
            BasicInput::Vector(element) => {
                let size = self.rng.gen_range(0, GEN_VEC_SIZE_MAX);
                MoveValue::Vector((0..size).map(|_| self.random_value(element)).collect())
            },
        }
    }

    /// Randomly mutate a Move value based on a basic input type
    pub fn mutate_value(&mut self, ty: &BasicInput, val: &MoveValue) -> MoveValue {
        match val {
            MoveValue::Bool(b) => MoveValue::Bool(!b),
            MoveValue::U8(v) => MoveValue::U8(mutate_int!(self, *v)),
            MoveValue::I8(v) => MoveValue::I8(mutate_int!(self, *v)),
            MoveValue::U16(v) => MoveValue::U16(mutate_int!(self, *v)),
            MoveValue::I16(v) => MoveValue::I16(mutate_int!(self, *v)),
            MoveValue::U32(v) => MoveValue::U32(mutate_int!(self, *v)),
            MoveValue::I32(v) => MoveValue::I32(mutate_int!(self, *v)),
            MoveValue::U64(v) => MoveValue::U64(mutate_int!(self, *v)),
            MoveValue::I64(v) => MoveValue::I64(mutate_int!(self, *v)),
            MoveValue::U128(v) => MoveValue::U128(mutate_int!(self, *v)),
            MoveValue::I128(v) => MoveValue::I128(mutate_int!(self, *v)),
            MoveValue::U256(v) => MoveValue::U256(mutate_int256!(self, U256, *v)),
            MoveValue::I256(v) => MoveValue::I256(mutate_int256!(self, I256, *v)),
            MoveValue::Address(_) => match ty {
                BasicInput::ObjectKnown { ident, .. } => {
                    MoveValue::Address(self.random_object_address_for(ident))
                },
                BasicInput::ObjectParam { .. } => {
                    MoveValue::Address(self.random_object_address_any())
                },
                _ => MoveValue::Address(self.random_address()),
            },
            MoveValue::Signer(_) => MoveValue::Signer(self.random_address()),
            MoveValue::Vector(elements) => {
                let elem_ty = match ty {
                    BasicInput::Vector(elem_ty) => elem_ty.as_ref(),
                    BasicInput::String => {
                        // special handling for string mutation
                        return self.mutate_string(elements);
                    },
                    _ => panic!("type mismatch when mutating MoveValue::Vector"),
                };
                if elements.is_empty() {
                    return MoveValue::Vector(vec![self.random_value(elem_ty)]);
                }
                if elements.len() >= GEN_VEC_SIZE_MAX as usize {
                    let index = self.rng.gen_range(0, elements.len());
                    let mut new_elements = elements.clone();
                    new_elements.swap_remove(index);
                    return MoveValue::Vector(new_elements);
                }

                let index = self.rng.gen_range(0, elements.len());
                let mut new_elements = elements.clone();

                let x = self.rng.gen_range(0, MUT_VEC_PROB_TOTAL);
                if x < MUT_VEC_PROB_ADD_ELEMENT {
                    new_elements.insert(index, self.random_value(elem_ty));
                    MoveValue::Vector(new_elements)
                } else if x < MUT_VEC_PROB_ADD_ELEMENT + MUT_VEC_PROB_DEL_ELEMENT {
                    new_elements.swap_remove(index);
                    MoveValue::Vector(new_elements)
                } else {
                    let elem = &new_elements[index];
                    new_elements[index] = self.mutate_value(elem_ty, elem);
                    MoveValue::Vector(new_elements)
                }
            },
            _ => todo!("mutate other MoveValue types"),
        }
    }

    /// Decide whether to mutate type arguments (~30% probability)
    pub fn should_mutate_type_args(&mut self) -> bool {
        self.rng.gen_range(0, 100) < MUT_TYPE_ARG_PROB
    }

    /// Randomly generate type arguments satisfying the given ability constraints
    pub fn random_type_args(&mut self, generics: &[AbilitySet]) -> Vec<VmTypeTag> {
        generics
            .iter()
            .map(|constraint| {
                let candidates = self.type_pool.candidates_for(*constraint);
                if candidates.is_empty() {
                    // fallback to u64 if no candidates match
                    VmTypeTag::U64
                } else {
                    let index = self.rng.gen_range(0, candidates.len());
                    candidates[index].clone()
                }
            })
            .collect()
    }

    /// Mutate type arguments by randomly replacing one type parameter with a different candidate
    pub fn mutate_type_args(
        &mut self,
        generics: &[AbilitySet],
        current: &[VmTypeTag],
    ) -> Vec<VmTypeTag> {
        assert_eq!(generics.len(), current.len());
        if generics.is_empty() {
            return vec![];
        }

        let mut result = current.to_vec();
        let pos = self.rng.gen_range(0, generics.len());
        let candidates = self.type_pool.candidates_for(generics[pos]);
        if candidates.len() > 1 {
            // pick a different candidate
            loop {
                let index = self.rng.gen_range(0, candidates.len());
                if *candidates[index] != current[pos] {
                    result[pos] = candidates[index].clone();
                    break;
                }
            }
        } else if !candidates.is_empty() {
            result[pos] = candidates[0].clone();
        }
        result
    }

    /// Randomly generate a Move string value
    fn random_string(&mut self) -> MoveValue {
        let x = self.rng.gen_range(0, GEN_STR_PROB_TOTAL);
        if x < GEN_STR_PROB_DICT {
            let idx = self.rng.gen_range(0, self.dict_string.len());
            str_to_move_bytes(&self.dict_string[idx])
        } else if x < GEN_STR_PROB_DICT + GEN_STR_PROB_EMPTY {
            MoveValue::Vector(vec![])
        } else {
            let len = self.rng.gen_range(1, GEN_STR_MAX_LEN + 1);
            MoveValue::Vector(
                (0..len)
                    .map(|_| MoveValue::U8(self.random_ascii_byte()))
                    .collect(),
            )
        }
    }

    /// Mutate a Move string (represented as vector<u8> elements)
    fn mutate_string(&mut self, elements: &[MoveValue]) -> MoveValue {
        let x = self.rng.gen_range(0, MUT_STR_PROB_TOTAL);
        if x < MUT_STR_PROB_ADD && elements.len() < GEN_STR_MAX_LEN {
            // insert a random ASCII byte at a random position
            let pos = self.rng.gen_range(0, elements.len() + 1);
            let byte = self.random_ascii_byte();
            let mut new = elements.to_vec();
            new.insert(pos, MoveValue::U8(byte));
            MoveValue::Vector(new)
        } else if x < MUT_STR_PROB_ADD + MUT_STR_PROB_DEL && !elements.is_empty() {
            // delete a byte at a random position
            let pos = self.rng.gen_range(0, elements.len());
            let mut new = elements.to_vec();
            new.remove(pos);
            MoveValue::Vector(new)
        } else if x < MUT_STR_PROB_ADD + MUT_STR_PROB_DEL + MUT_STR_PROB_CHANGE
            && !elements.is_empty()
        {
            // change a byte at a random position
            let pos = self.rng.gen_range(0, elements.len());
            let byte = self.random_ascii_byte();
            let mut new = elements.to_vec();
            new[pos] = MoveValue::U8(byte);
            MoveValue::Vector(new)
        } else {
            // replace with a dictionary string
            let idx = self.rng.gen_range(0, self.dict_string.len());
            str_to_move_bytes(&self.dict_string[idx])
        }
    }

    /// Generate a random printable ASCII byte
    fn random_ascii_byte(&mut self) -> u8 {
        self.rng.gen_range(0x20u8, 0x7Fu8)
    }

    /// Get a random address
    fn random_address(&mut self) -> AccountAddress {
        loop {
            let x = self.rng.gen_range(0, GEN_ADDR_PROB_TOTAL);
            let kind = if x < GEN_ADDR_PROB_NAME_PRIMARY {
                AddressKind::Named(NamedAddressKind::Primary)
            } else if x < GEN_ADDR_PROB_NAME_DEPENDENCY {
                AddressKind::Named(NamedAddressKind::Dependency)
            } else if x < GEN_ADDR_PROB_NAME_FRAMEWORK {
                AddressKind::Named(NamedAddressKind::Framework)
            } else {
                AddressKind::User
            };

            let addrs = match self.dict_address.get(&kind) {
                None => continue,
                Some(v) => v,
            };
            if addrs.is_empty() {
                continue;
            }

            let index = self.rng.gen_range(0, addrs.len());
            return *addrs.iter().nth(index).unwrap();
        }
    }

    /// Get a random address out of which we can create a signer
    pub fn random_signer(&mut self) -> AccountAddress {
        self.random_address()
    }

    /// Generate a random percentage value in [0, 100)
    pub fn random_percent(&mut self) -> u8 {
        self.rng.gen_range(0u8, 100)
    }

    /// Get a mutable reference to the internal RNG
    pub fn rng_mut(&mut self) -> &mut StdRng {
        &mut self.rng
    }

    /// Update the object dictionary from write set resource writes.
    ///
    /// Pass 1: identify object addresses (those with ObjectGroup resource group).
    /// Pass 2: record resource-type-to-address mappings for known objects.
    pub fn update_object_dict(&mut self, writes: &[ResourceWrite]) {
        // Pass 1: find new object addresses via ObjectGroup resource group writes
        for ResourceWrite {
            address,
            struct_tag,
            is_resource_group,
        } in writes
        {
            if *is_resource_group
                && struct_tag.address == AccountAddress::ONE
                && struct_tag.module.as_str() == "object"
                && struct_tag.name.as_str() == "ObjectGroup"
            {
                self.object_addresses.insert(*address);
            }
        }

        // Pass 2: for resources written at known object addresses, record the mapping
        for ResourceWrite {
            address,
            struct_tag,
            is_resource_group,
        } in writes
        {
            if !is_resource_group && self.object_addresses.contains(address) {
                let ident = DatatypeIdent::from_struct_tuple(
                    struct_tag.address,
                    struct_tag.module.clone(),
                    struct_tag.name.clone(),
                );
                self.dict_object.entry(ident).or_default().insert(*address);
            }
        }
    }

    /// Get a random object address for a known object type
    fn random_object_address_for(&mut self, ident: &DatatypeIdent) -> AccountAddress {
        if let Some(addrs) = self.dict_object.get(ident) {
            if !addrs.is_empty() {
                let index = self.rng.gen_range(0, addrs.len());
                return *addrs.iter().nth(index).unwrap();
            }
        }
        self.random_object_address_any()
    }

    /// Get a random object address from any known object
    fn random_object_address_any(&mut self) -> AccountAddress {
        if !self.object_addresses.is_empty() {
            let index = self.rng.gen_range(0, self.object_addresses.len());
            return *self.object_addresses.iter().nth(index).unwrap();
        }
        self.random_address()
    }
}

/// Utility: convert a string to a Move byte vector
#[inline]
fn str_to_move_bytes(s: &str) -> MoveValue {
    MoveValue::Vector(s.bytes().map(MoveValue::U8).collect())
}
