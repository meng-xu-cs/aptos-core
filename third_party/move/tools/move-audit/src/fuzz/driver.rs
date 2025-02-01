use crate::fuzz::{
    canvas::{ComplexType, DriverCanvas, TypeClosureBase, TypeClosureItem},
    entrypoint::{FunctionDecl, FunctionInst, FunctionRegistry},
    typing::{DatatypeRegistry, TypeBase, TypeItem, TypeUnifier, VectorVariant},
};
use std::collections::BTreeMap;

/// A driver generator that also caches information during driver generation
pub struct DriverGenerator<'a> {
    // information registry
    datatype_registry: &'a DatatypeRegistry,
    function_registry: &'a FunctionRegistry,

    // canvas for entrypoint functions
    canvas_mapping: BTreeMap<FunctionInst, DriverCanvas>,
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
            canvas_mapping: BTreeMap::new(),
        }
    }

    /// Check if an instantiation has been analyzed
    pub fn has_function_inst(&self, inst: &FunctionInst) -> bool {
        self.canvas_mapping.contains_key(inst)
    }

    /// Analyze the function instantiation and update the stateful variables
    pub fn analyze_function_inst(&mut self, decl: &FunctionDecl, inst: &FunctionInst) -> bool {
        debug_assert_eq!(decl.ident, inst.ident);

        // further instantiate parameter and return types
        let params: Vec<_> = decl
            .parameters
            .iter()
            .map(|t| {
                TypeClosureItem::from(
                    self.datatype_registry
                        .instantiate_type_ref(t, &inst.type_args),
                )
            })
            .collect();
        let ret_ty: Vec<_> = decl
            .return_sig
            .iter()
            .map(|t| {
                TypeClosureItem::from(
                    self.datatype_registry
                        .instantiate_type_ref(t, &inst.type_args),
                )
            })
            .collect();

        // initialize the base canvas
        let mut canvas = DriverCanvas::new();

        // prepare canvas for the arguments
        for item in &params {
            match item {
                TypeClosureItem::Base(TypeClosureBase::Simple(t)) => {
                    canvas.add_input_simple_recursive(t, 0);
                },
                TypeClosureItem::ImmRef(TypeClosureBase::Simple(t)) => {
                    let var = canvas.add_input_simple_recursive(t, 0);
                    canvas.new_stmt_imm_borrow(var);
                },
                TypeClosureItem::MutRef(TypeClosureBase::Simple(t)) => {
                    let var = canvas.add_input_simple_recursive(t, 0);
                    canvas.new_stmt_mut_borrow(var);
                },
                TypeClosureItem::Base(TypeClosureBase::Complex(t)) => {
                    // TODO: if type is copy-able, we can also search for refs
                    // log::info!("function {inst} requires {}", TypeBase::from(t.clone()));

                    // search for a provider
                    match self.probe_providers_complex(t) {
                        None => return false,
                        Some(()) => (),
                    }
                },
                TypeClosureItem::ImmRef(TypeClosureBase::Complex(t)) => {
                    // TODO
                    // log::info!("function {inst} requires &{}", TypeBase::from(t.clone()));
                    return false;
                },
                TypeClosureItem::MutRef(TypeClosureBase::Complex(t)) => {
                    // TODO
                    // log::info!("function {inst} requires &mut {}",TypeBase::from(t.clone()));
                    return false;
                },
            }
        }

        // see which datatype this function can provide
        for (i, item) in ret_ty.iter().enumerate() {
            match item {
                TypeClosureItem::Base(TypeClosureBase::Simple(_)) => continue,
                TypeClosureItem::Base(TypeClosureBase::Complex(t)) => {
                    // TODO
                    let t = TypeBase::from(t.clone());
                    if t.abilities().has_drop() {
                        continue;
                    }
                    log::info!("function {inst} needs to deposit {t}",);
                },
                TypeClosureItem::ImmRef(_) | TypeClosureItem::MutRef(_) => {
                    // TODO
                    continue;
                },
            }
        }

        // done with the analysis
        let existing = self.canvas_mapping.insert(inst.clone(), canvas);
        assert!(existing.is_none());
        true
    }

    fn probe_providers_complex(&mut self, datatype: &ComplexType) -> Option<()> {
        // TODO: check if we have cached it
        None
    }
}
