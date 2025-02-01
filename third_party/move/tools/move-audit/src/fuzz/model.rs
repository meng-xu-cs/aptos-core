use crate::{
    common::PkgDefinition,
    fuzz::{
        canvas::{TypeClosureBase, TypeClosureItem},
        driver::DriverGenerator,
        entrypoint::{FunctionDecl, FunctionInst, FunctionRegistry},
        typing::DatatypeRegistry,
    },
};
use itertools::Itertools;
use move_compiler::compiled_unit::CompiledUnit;
use move_package::compilation::compiled_package::CompiledUnitWithSource;
use std::collections::BTreeSet;

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

        // collect instantiations of entrypoint functions
        let mut primary_entrypoint_instantiations = BTreeSet::new();
        for decl in function_registry.iter_decls() {
            if !decl.is_primary {
                continue;
            }

            for inst in
                collect_function_instantiations(&datatype_registry, decl, type_recursion_depth)
            {
                self.analyze_function_instantiation(&datatype_registry, decl, &inst);
                let inserted = primary_entrypoint_instantiations.insert(inst);
                assert!(inserted);
            }
        }

        // initialize the generator
        let mut generator = DriverGenerator::new(&datatype_registry, &function_registry);
    }

    fn analyze_function_instantiation(
        &mut self,
        datatype_registry: &DatatypeRegistry,
        decl: &FunctionDecl,
        inst: &FunctionInst,
    ) {
        debug_assert_eq!(decl.ident, inst.ident);

        // instantiate parameter and return types
        let params: Vec<_> = decl
            .parameters
            .iter()
            .map(|t| {
                TypeClosureItem::from(datatype_registry.instantiate_type_ref(t, &inst.type_args))
            })
            .collect();
        let ret_ty: Vec<_> = decl
            .return_sig
            .iter()
            .map(|t| {
                TypeClosureItem::from(datatype_registry.instantiate_type_ref(t, &inst.type_args))
            })
            .collect();

        // prepare canvas for the arguments
        for item in &params {
            match item {
                TypeClosureItem::Base(TypeClosureBase::Simple(_))
                | TypeClosureItem::ImmRef(TypeClosureBase::Simple(_))
                | TypeClosureItem::MutRef(TypeClosureBase::Simple(_)) => (),
                TypeClosureItem::Base(TypeClosureBase::Complex(t)) => {
                    // TODO: if type is copy-able, we can also search for refs
                    // log::info!("function {inst} requires {}", TypeBase::from(t.clone()));
                },
                TypeClosureItem::ImmRef(TypeClosureBase::Complex(t)) => {
                    // TODO
                    // log::info!("function {inst} requires &{}", TypeBase::from(t.clone()));
                },
                TypeClosureItem::MutRef(TypeClosureBase::Complex(t)) => {
                    // TODO
                    // log::info!("function {inst} requires &mut {}",TypeBase::from(t.clone()));
                },
            }
        }
    }
}

/// Utility: collect possible function instantiations
fn collect_function_instantiations(
    datatype_registry: &DatatypeRegistry,
    decl: &FunctionDecl,
    type_recursion_depth: usize,
) -> Vec<FunctionInst> {
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
        let ty_args =
            datatype_registry.type_bases_by_ability_constraint(*constraint, type_recursion_depth);
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
