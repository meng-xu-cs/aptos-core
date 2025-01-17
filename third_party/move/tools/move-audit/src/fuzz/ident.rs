use move_core_types::{account_address::AccountAddress, identifier::Identifier};
use std::fmt::Display;

/// A unique identifier for a module
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct ModuleIdent {
    pub address: AccountAddress,
    pub name: Identifier,
}

impl Display for ModuleIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.address, self.name)
    }
}

/// A unique identifier for a datatype
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct DatatypeIdent {
    pub module: ModuleIdent,
    pub datatype: Identifier,
}

impl Display for DatatypeIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.module, self.datatype)
    }
}

/// A unique identifier for a function
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct FunctionIdent {
    pub module: ModuleIdent,
    pub function: Identifier,
}

impl Display for FunctionIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.module, self.function)
    }
}
