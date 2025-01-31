use crate::{
    common::PkgDefinition,
    fuzz::{driver::DriverGenerator, entrypoint::FunctionRegistry, typing::DatatypeRegistry},
};
use move_compiler::compiled_unit::CompiledUnit;
use move_package::compilation::compiled_package::CompiledUnitWithSource;
use std::collections::BTreeMap;

/// A database that holds information we can statically get from the packages
pub struct Model {}

impl Model {
    /// Initialize the model to an empty state
    pub fn new() -> Self {
        Self {}
    }

    /// Analyze a closure of packages
    pub fn provision(&mut self, pkgs: &[PkgDefinition], type_recursion_depth: usize) {
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

        // initialize the generator
        let mut generator =
            DriverGenerator::new(&datatype_registry, &function_registry, type_recursion_depth);

        // start with collecting instantiations
        let mut primary_function_instantiations = BTreeMap::new();
        for decl in function_registry.iter_decls() {
            if !decl.is_primary {
                continue;
            }
            let insts = generator.collect_function_insts(decl);
            let existing = primary_function_instantiations.insert(decl.clone(), insts);
            assert!(existing.is_none());
        }

        // fixedpoint iteration to deduce the scripts we can generate
        loop {
            let mut num_added = 0;
            for (decl, insts) in primary_function_instantiations.iter() {
                for inst in insts {
                    if generator.has_function_inst(inst) {
                        continue;
                    }
                    if generator.analyze_function_inst(decl, inst) {
                        num_added += 1;
                    }
                }
            }

            if num_added == 0 {
                break;
            }

            // otherwise, continue with a new round of iteration
            log::debug!("number of primary function analyzed: {num_added}",);
        }
    }
}
