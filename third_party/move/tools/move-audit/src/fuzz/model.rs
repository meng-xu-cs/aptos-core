use crate::{
    common::PkgDefinition,
    fuzz::{entrypoint::FunctionRegistry, typing::DatatypeRegistry},
};
use move_compiler::compiled_unit::CompiledUnit;
use move_package::compilation::compiled_package::CompiledUnitWithSource;

/// A database that holds information we can statically get from the packages
pub struct Model {
    datatype_registry: DatatypeRegistry,
    function_registry: FunctionRegistry,
}

impl Model {
    /// Initialize the model to an empty state
    pub fn new() -> Self {
        Self {
            datatype_registry: DatatypeRegistry::new(),
            function_registry: FunctionRegistry::new(),
        }
    }

    /// Analyze a closure of packages
    pub fn provision(&mut self, pkgs: &[PkgDefinition]) {
        // initialize the datatype registry
        for pkg in pkgs {
            for CompiledUnitWithSource {
                unit,
                source_path: _,
            } in &pkg.as_built_package().package.root_compiled_units
            {
                let module = match unit {
                    CompiledUnit::Script(_) => continue,
                    CompiledUnit::Module(m) => &m.module,
                };

                // go over all datatypes defined
                self.datatype_registry.analyze(module);
            }
        }

        // initialize the function registry
        for pkg in pkgs {
            let is_primary = matches!(pkg, PkgDefinition::Primary(_));
            for CompiledUnitWithSource {
                unit,
                source_path: _,
            } in &pkg.as_built_package().package.root_compiled_units
            {
                let module = match unit {
                    CompiledUnit::Script(_) => continue,
                    CompiledUnit::Module(m) => &m.module,
                };

                // go over all datatypes defined
                self.function_registry
                    .analyze(&self.datatype_registry, module, is_primary);
            }
        }
    }
}
