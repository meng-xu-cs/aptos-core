use crate::fuzz::{
    entrypoint::{FunctionDecl, FunctionRegistry},
    typing::DatatypeRegistry,
};

/// A driver generator that also caches information during driver generation
pub struct DriverGenerator<'a> {
    datatype_registry: &'a DatatypeRegistry,
    function_registry: &'a FunctionRegistry,
}

impl<'a> DriverGenerator<'a> {
    /// Create a new generator with necessary information
    pub fn new(
        datatype_registry: &'a DatatypeRegistry,
        function_registry: &'a FunctionRegistry,
    ) -> Self {
        Self {
            datatype_registry,
            function_registry,
        }
    }

    /// Generate drivers (which could be zero to multiple) for an entrypoint
    pub fn generate(&mut self, decl: &FunctionDecl) {
        log::debug!("generating driver for {}", decl.ident);

        // check for potential instantiations
    }
}
