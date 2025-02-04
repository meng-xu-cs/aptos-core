use crate::{
    common::PkgDefinition,
    fuzz::{
        canvas::{ComplexType, SimpleType, TypeClosureBase, TypeClosureItem},
        driver::DriverGenerator,
        function::{FunctionDecl, FunctionInst, FunctionRegistry},
        typing::{DatatypeRegistry, MapVariant, TypeBase, TypeItem, VectorVariant},
    },
};
use itertools::Itertools;
use move_compiler::compiled_unit::CompiledUnit;
use move_package::compilation::compiled_package::CompiledUnitWithSource;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
enum DatatypeItem {
    Base(ComplexType),
    ImmRef(ComplexType),
    MutRef(ComplexType),
}

impl From<DatatypeItem> for TypeItem {
    fn from(value: DatatypeItem) -> Self {
        match value {
            DatatypeItem::Base(t) => TypeItem::Base(t.into()),
            DatatypeItem::ImmRef(t) => TypeItem::ImmRef(t.into()),
            DatatypeItem::MutRef(t) => TypeItem::MutRef(t.into()),
        }
    }
}

enum DPGNode {
    Function(FunctionInst),
    Datatype(DatatypeItem),
}

enum DPGEdge {
    Use(usize),
    Def(usize),
    OptionToElement,
    ElementToOption,
    VectorToElement {
        variant: VectorVariant,
    },
    ElementToVector {
        variant: VectorVariant,
    },
    MapToKey {
        variant: MapVariant,
    },
    KeyToMapSimple {
        value: SimpleType,
        variant: MapVariant,
    },
    KeyToMapComplex {
        value: NodeIndex,
        variant: MapVariant,
    },
    MapToValue {
        variant: MapVariant,
    },
    ValueToMapSimple {
        key: SimpleType,
        variant: MapVariant,
    },
    ValueToMapComplex {
        key: NodeIndex,
        variant: MapVariant,
    },
    Deref,
    ImmBorrow,
    MutBorrow,
}

/// A database that holds information we can statically get from the packages
pub struct Model {
    datatype_provider_graph: DiGraph<DPGNode, DPGEdge>,
    datatype_item_to_node_id: BTreeMap<DatatypeItem, NodeIndex>,
    function_inst_to_node_id: BTreeMap<FunctionInst, NodeIndex>,
}

impl Model {
    /// Initialize the model to an empty state
    pub fn new() -> Self {
        Self {
            datatype_provider_graph: DiGraph::new(),
            datatype_item_to_node_id: BTreeMap::new(),
            function_inst_to_node_id: BTreeMap::new(),
        }
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
        for decl in function_registry.iter_decls() {
            let insts =
                collect_function_instantiations(&datatype_registry, decl, type_recursion_depth);
            for inst in insts {
                log::debug!("analyzing function instantiation {inst}");
                self.analyze_function_instantiation(&datatype_registry, decl, inst);
            }
        }

        // initialize the generator
        let mut generator = DriverGenerator::new(&datatype_registry, &function_registry);
    }

    fn analyze_datatype_item(&mut self, item: DatatypeItem) -> NodeIndex {
        match self.datatype_item_to_node_id.get(&item) {
            None => {},
            Some(index) => return *index,
        }
        log::debug!("analyzing datatype item {}", TypeItem::from(item.clone()));

        let index = self
            .datatype_provider_graph
            .add_node(DPGNode::Datatype(item.clone()));
        self.datatype_item_to_node_id.insert(item.clone(), index);

        // now analyze this item
        match item {
            DatatypeItem::Base(t) => match t {
                ComplexType::Unit { .. } => (),
                ComplexType::Option { element } => {
                    let element_index = self.analyze_datatype_item(DatatypeItem::Base(*element));
                    self.datatype_provider_graph.add_edge(
                        index,
                        element_index,
                        DPGEdge::OptionToElement,
                    );
                    self.datatype_provider_graph.add_edge(
                        element_index,
                        index,
                        DPGEdge::ElementToOption,
                    );
                },
                ComplexType::Vector { element, variant } => {
                    let element_index = self.analyze_datatype_item(DatatypeItem::Base(*element));
                    self.datatype_provider_graph.add_edge(
                        index,
                        element_index,
                        DPGEdge::VectorToElement { variant },
                    );
                    self.datatype_provider_graph.add_edge(
                        element_index,
                        index,
                        DPGEdge::ElementToVector { variant },
                    );
                },
                ComplexType::MapOnKey {
                    key,
                    value,
                    variant,
                } => {
                    let key_index = self.analyze_datatype_item(DatatypeItem::Base(*key));
                    self.datatype_provider_graph
                        .add_edge(index, key_index, DPGEdge::MapToKey { variant });
                    self.datatype_provider_graph.add_edge(
                        key_index,
                        index,
                        DPGEdge::KeyToMapSimple { value, variant },
                    );
                },
                ComplexType::MapOnValue {
                    key,
                    value,
                    variant,
                } => {
                    let value_index = self.analyze_datatype_item(DatatypeItem::Base(*value));
                    self.datatype_provider_graph.add_edge(
                        index,
                        value_index,
                        DPGEdge::MapToValue { variant },
                    );
                    self.datatype_provider_graph.add_edge(
                        value_index,
                        index,
                        DPGEdge::ValueToMapSimple { key, variant },
                    );
                },
                ComplexType::MapOnBoth {
                    key,
                    value,
                    variant,
                } => {
                    let key_index = self.analyze_datatype_item(DatatypeItem::Base(*key));
                    let value_index = self.analyze_datatype_item(DatatypeItem::Base(*value));
                    self.datatype_provider_graph
                        .add_edge(index, key_index, DPGEdge::MapToKey { variant });
                    self.datatype_provider_graph.add_edge(
                        index,
                        value_index,
                        DPGEdge::MapToValue { variant },
                    );
                    self.datatype_provider_graph.add_edge(
                        key_index,
                        index,
                        DPGEdge::KeyToMapComplex {
                            value: value_index,
                            variant,
                        },
                    );
                    self.datatype_provider_graph.add_edge(
                        value_index,
                        index,
                        DPGEdge::ValueToMapComplex {
                            key: key_index,
                            variant,
                        },
                    );
                },
            },
            DatatypeItem::ImmRef(t) => {
                let abilities = TypeBase::from(t.clone()).abilities();
                let base_index = self.analyze_datatype_item(DatatypeItem::Base(t));
                self.datatype_provider_graph
                    .add_edge(base_index, index, DPGEdge::ImmBorrow);
                if abilities.has_copy() {
                    self.datatype_provider_graph
                        .add_edge(index, base_index, DPGEdge::Deref);
                }
            },
            DatatypeItem::MutRef(t) => {
                let abilities = TypeBase::from(t.clone()).abilities();
                let base_index = self.analyze_datatype_item(DatatypeItem::Base(t));
                self.datatype_provider_graph
                    .add_edge(base_index, index, DPGEdge::MutBorrow);
                if abilities.has_copy() {
                    self.datatype_provider_graph
                        .add_edge(index, base_index, DPGEdge::Deref);
                }
            },
        }

        // done with the analysis
        index
    }

    fn analyze_function_instantiation(
        &mut self,
        datatype_registry: &DatatypeRegistry,
        decl: &FunctionDecl,
        inst: FunctionInst,
    ) {
        assert_eq!(decl.ident, inst.ident);

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

        // create a new node that represent this function instantiation
        let node_index = self
            .datatype_provider_graph
            .add_node(DPGNode::Function(inst.clone()));
        let existing = self.function_inst_to_node_id.insert(inst, node_index);
        assert!(existing.is_none());

        // populate edges in the graph
        for (i, item) in params.iter().enumerate() {
            let item_index = match item {
                TypeClosureItem::Base(TypeClosureBase::Simple(_))
                | TypeClosureItem::ImmRef(TypeClosureBase::Simple(_))
                | TypeClosureItem::MutRef(TypeClosureBase::Simple(_)) => continue,
                TypeClosureItem::Base(TypeClosureBase::Complex(t)) => {
                    self.analyze_datatype_item(DatatypeItem::Base(t.clone()))
                },
                TypeClosureItem::ImmRef(TypeClosureBase::Complex(t)) => {
                    self.analyze_datatype_item(DatatypeItem::ImmRef(t.clone()))
                },
                TypeClosureItem::MutRef(TypeClosureBase::Complex(t)) => {
                    self.analyze_datatype_item(DatatypeItem::MutRef(t.clone()))
                },
            };
            self.datatype_provider_graph
                .add_edge(item_index, node_index, DPGEdge::Use(i));
        }

        for (i, item) in ret_ty.iter().enumerate() {
            let item_index = match item {
                TypeClosureItem::Base(TypeClosureBase::Simple(_))
                | TypeClosureItem::ImmRef(TypeClosureBase::Simple(_))
                | TypeClosureItem::MutRef(TypeClosureBase::Simple(_)) => continue,
                TypeClosureItem::Base(TypeClosureBase::Complex(t)) => {
                    self.analyze_datatype_item(DatatypeItem::Base(t.clone()))
                },
                TypeClosureItem::ImmRef(TypeClosureBase::Complex(t)) => {
                    self.analyze_datatype_item(DatatypeItem::ImmRef(t.clone()))
                },
                TypeClosureItem::MutRef(TypeClosureBase::Complex(t)) => {
                    self.analyze_datatype_item(DatatypeItem::MutRef(t.clone()))
                },
            };
            self.datatype_provider_graph
                .add_edge(node_index, item_index, DPGEdge::Def(i));
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
