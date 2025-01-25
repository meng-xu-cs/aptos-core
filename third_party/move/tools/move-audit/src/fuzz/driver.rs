use crate::fuzz::{
    entrypoint::{FunctionDecl, FunctionRegistry},
    ident::FunctionIdent,
    typing::{DatatypeRegistry, TypeBase, TypeTag},
};
use itertools::Itertools;
use std::fmt::Display;

/// Instantiation of a function
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub struct FunctionInst {
    ident: FunctionIdent,
    type_args: Vec<TypeBase>,
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

/// A driver generator that also caches information during driver generation
pub struct DriverGenerator<'a> {
    datatype_registry: &'a DatatypeRegistry,
    function_registry: &'a FunctionRegistry,
    type_recursion_depth: usize,
}

impl<'a> DriverGenerator<'a> {
    /// Create a new generator with necessary information
    pub fn new(
        datatype_registry: &'a DatatypeRegistry,
        function_registry: &'a FunctionRegistry,
        type_recursion_depth: usize,
    ) -> Self {
        Self {
            datatype_registry,
            function_registry,
            type_recursion_depth,
        }
    }

    /// Collect possible function instantiations
    fn collect_function_insts(&self, decl: &FunctionDecl) -> Vec<FunctionInst> {
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
            let ty_args = self
                .datatype_registry
                .type_bases_by_ability_constraint(*constraint, self.type_recursion_depth);
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

    /// Generate drivers (zero to multiple) for an entrypoint instance
    fn generate_drivers_for_inst(&mut self, decl: &FunctionDecl, inst: &FunctionInst) {
        debug_assert_eq!(decl.ident, inst.ident);
        log::debug!("deriving script for {inst}");

        // further instantiate parameter and return types
        let params: Vec<_> = decl
            .parameters
            .iter()
            .map(|t| {
                self.datatype_registry
                    .instantiate_type_ref(t, &inst.type_args)
            })
            .collect();
        let ret_ty: Vec<_> = decl
            .return_sig
            .iter()
            .map(|t| {
                self.datatype_registry
                    .instantiate_type_ref(t, &inst.type_args)
            })
            .collect();

        // check if this is trivial
    }

    /// Generate drivers (zero to multiple) for an entrypoint declaration
    pub fn generate_drivers_for_decl(&mut self, decl: &FunctionDecl) {
        // derive instantiations
        for inst in self.collect_function_insts(decl) {
            self.generate_drivers_for_inst(decl, &inst);
        }
    }
}
