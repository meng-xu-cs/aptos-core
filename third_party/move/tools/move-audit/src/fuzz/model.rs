use crate::{
    common::PkgDefinition,
    fuzz::{driver::DriverGenerator, entrypoint::FunctionRegistry, typing::DatatypeRegistry},
};
use move_compiler::compiled_unit::CompiledUnit;
use move_package::compilation::compiled_package::CompiledUnitWithSource;

/// A database that holds information we can statically get from the packages
pub struct Model {}

impl Model {
    /// Initialize the model to an empty state
    pub fn new() -> Self {
        Self {}
    }

    /// Analyze a closure of packages
    pub fn provision(&mut self, pkgs: &[PkgDefinition]) {
        // initialize the datatype registry
        let mut datatype_registry = DatatypeRegistry::new();
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
                datatype_registry.analyze(module, is_primary);
            }
        }

        // initialize the function registry
        let mut function_registry = FunctionRegistry::new();
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
                function_registry.analyze(&datatype_registry, module, is_primary);
            }
        }

        // generate fuzzing drivers for each and every primary function
        let mut generator = DriverGenerator::new(&datatype_registry, &function_registry);
        for decl in function_registry.iter_decls() {
            if !decl.is_primary() {
                continue;
            }
            generator.generate(decl);
        }
    }
}
