use move_binary_format::{
    access::ModuleAccess,
    file_format::{FunctionHandle, ModuleHandle, StructHandle},
    CompiledModule,
};
use move_core_types::{account_address::AccountAddress, identifier::Identifier};
use std::fmt::Display;

/// A unique identifier for a module
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct ModuleIdent {
    address: AccountAddress,
    name: Identifier,
}

impl ModuleIdent {
    /// Utility conversion from the corresponding handle in file_format
    pub fn from_module_handle(module: &CompiledModule, handle: &ModuleHandle) -> Self {
        Self {
            address: *module.address_identifier_at(handle.address),
            name: module.identifier_at(handle.name).to_owned(),
        }
    }
}

impl Display for ModuleIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.address, self.name)
    }
}

/// A unique identifier for a datatype
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct DatatypeIdent {
    module: ModuleIdent,
    datatype: Identifier,
}

impl DatatypeIdent {
    /// Utility conversion from the corresponding handle in file_format
    pub fn from_struct_handle(module: &CompiledModule, handle: &StructHandle) -> Self {
        Self {
            module: ModuleIdent::from_module_handle(module, module.module_handle_at(handle.module)),
            datatype: module.identifier_at(handle.name).to_owned(),
        }
    }

    /// Get the address
    pub fn address(&self) -> AccountAddress {
        self.module.address
    }

    /// Get the module name
    pub fn module_name(&self) -> &str {
        self.module.name.as_str()
    }

    /// Get the datatype name
    pub fn datatype_name(&self) -> &str {
        self.datatype.as_str()
    }
}

impl Display for DatatypeIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.module, self.datatype)
    }
}

/// A unique identifier for a function
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct FunctionIdent {
    module: ModuleIdent,
    function: Identifier,
}

impl FunctionIdent {
    /// Utility conversion from the corresponding handle in file_format
    pub fn from_function_handle(module: &CompiledModule, handle: &FunctionHandle) -> Self {
        Self {
            module: ModuleIdent::from_module_handle(module, module.module_handle_at(handle.module)),
            function: module.identifier_at(handle.name).to_owned(),
        }
    }

    /// Get the address
    pub fn address(&self) -> AccountAddress {
        self.module.address
    }

    /// Get the module name
    pub fn module_name(&self) -> &str {
        self.module.name.as_str()
    }

    /// Get the function name
    pub fn function_name(&self) -> &str {
        self.function.as_str()
    }
}

impl Display for FunctionIdent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}::{}", self.module, self.function)
    }
}
