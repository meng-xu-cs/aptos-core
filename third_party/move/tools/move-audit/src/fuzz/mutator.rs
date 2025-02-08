use crate::fuzz::{
    account::{AddressKind, NamedAddressKind},
    prep::RuntimeType,
};
use move_core_types::{
    account_address::AccountAddress,
    u256,
    value::{MoveStruct, MoveValue},
};
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::collections::{BTreeMap, BTreeSet};

// Probabilities and configurations
const GEN_INT_PROB_MIN: u8 = 10;
const GEN_INT_PROB_MAX: u8 = 10;
const GEN_INT_PROB_ANY: u8 = 80;
const GEN_INT_PROB_TOTAL: u8 = GEN_INT_PROB_MIN + GEN_INT_PROB_MAX + GEN_INT_PROB_ANY;

const GEN_VEC_SIZE_MAX: u8 = 8;

const GEN_ADDR_PROB_NAME_PRIMARY: u8 = 40;
const GEN_ADDR_PROB_NAME_DEPENDENCY: u8 = 10;
const GEN_ADDR_PROB_NAME_FRAMEWORK: u8 = 5;
const GEN_ADDR_PROB_USER: u8 = 45;
const GEN_ADDR_PROB_TOTAL: u8 = GEN_ADDR_PROB_NAME_PRIMARY
    + GEN_ADDR_PROB_NAME_DEPENDENCY
    + GEN_ADDR_PROB_NAME_FRAMEWORK
    + GEN_ADDR_PROB_USER;

macro_rules! create_int {
    ($s:expr, $t:ty) => {{
        let x = $s.rng.gen_range(0, GEN_INT_PROB_TOTAL);
        if x < GEN_INT_PROB_MIN {
            <$t>::MIN
        } else if x >= GEN_INT_PROB_MAX {
            <$t>::MAX
        } else {
            $s.rng.gen()
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

/// Input generator and mutator
pub struct Mutator {
    // random number generator
    rng: StdRng,

    // dictionaries
    dict_address: BTreeMap<AddressKind, BTreeSet<AccountAddress>>,
}

impl Mutator {
    /// Create a new random mutator
    pub fn new(
        seed: u64,
        dict_address: BTreeMap<AddressKind, BTreeSet<AccountAddress>>,
    ) -> Mutator {
        Self {
            rng: StdRng::seed_from_u64(seed),
            dict_address,
        }
    }

    /// Randomly generate a Move value based on a runtime type
    pub fn random_value(&mut self, ty: &RuntimeType) -> MoveValue {
        match ty {
            RuntimeType::Bool => MoveValue::Bool(self.rng.gen()),
            RuntimeType::U8 => MoveValue::U8(create_int!(self, u8)),
            RuntimeType::U16 => MoveValue::U16(create_int!(self, u16)),
            RuntimeType::U32 => MoveValue::U32(create_int!(self, u32)),
            RuntimeType::U64 => MoveValue::U64(create_int!(self, u64)),
            RuntimeType::U128 => MoveValue::U128(create_int!(self, u128)),
            RuntimeType::U256 => MoveValue::U256(create_int!(
                self,
                u256::U256::zero(),
                u256::U256::max_value(),
                u256::U256::from_le_bytes(&self.rng.gen())
            )),
            RuntimeType::Bitvec => {
                let size = self.rng.gen_range(0, GEN_VEC_SIZE_MAX);
                MoveValue::Vector(
                    (0..size)
                        .map(|_| self.random_value(&RuntimeType::Bool))
                        .collect(),
                )
            },
            RuntimeType::String => {
                // TODO: use the string dictionary
                MoveValue::Vector(vec![])
            },
            RuntimeType::Address => MoveValue::Address(self.random_address()),
            RuntimeType::Signer => MoveValue::Signer(self.random_signer()),
            RuntimeType::Option(inner) => {
                if self.rng.gen() {
                    MoveValue::Vector(vec![])
                } else {
                    MoveValue::Vector(vec![self.random_value(inner)])
                }
            },
            RuntimeType::Vector(element) => {
                let size = self.rng.gen_range(0, GEN_VEC_SIZE_MAX);
                MoveValue::Vector((0..size).map(|_| self.random_value(element)).collect())
            },
            RuntimeType::Object(..) => {
                // TODO: use the object dictionary
                MoveValue::Address(AccountAddress::ZERO)
            },
            RuntimeType::Struct(fields) => MoveValue::Struct(MoveStruct::Runtime(
                fields.iter().map(|t| self.random_value(t)).collect(),
            )),
            RuntimeType::Enum(variants) => {
                let index = self.rng.gen_range(0, variants.len());
                MoveValue::Struct(MoveStruct::RuntimeVariant(
                    index as u16,
                    variants[index]
                        .iter()
                        .map(|t| self.random_value(t))
                        .collect(),
                ))
            },
        }
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
}
