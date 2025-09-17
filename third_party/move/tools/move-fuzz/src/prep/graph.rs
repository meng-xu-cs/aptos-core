// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::prep::{
    function::FunctionDecl,
    ident::FunctionIdent,
    model::Model,
    typing::{ComplexType, MapVariant, SimpleType, TypeBase, TypeItem, TypeMode, VectorVariant},
};
use itertools::Itertools;
use petgraph::{
    algo::is_cyclic_directed,
    graph::{DiGraph, NodeIndex},
    Direction,
};
use std::{collections::BTreeSet, fmt::Display, mem};

/// Datatype node
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
enum DatatypeItem {
    Base(ComplexType),
    ImmRef(ComplexType),
    MutRef(ComplexType),
}

impl DatatypeItem {
    fn from_type_base(ty: &TypeItem) -> Option<Self> {
        let converted = match ty {
            TypeItem::Base(t) => match TypeMode::convert(t) {
                TypeMode::Simple(_) => return None,
                TypeMode::Complex(complex_ty) => Self::Base(complex_ty),
            },
            TypeItem::ImmRef(t) => match TypeMode::convert(t) {
                TypeMode::Simple(_) => return None,
                TypeMode::Complex(complex_ty) => Self::ImmRef(complex_ty),
            },
            TypeItem::MutRef(t) => match TypeMode::convert(t) {
                TypeMode::Simple(_) => return None,
                TypeMode::Complex(complex_ty) => Self::MutRef(complex_ty),
            },
        };
        Some(converted)
    }
}

/// Function instantiation node
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
struct FunctionInst {
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

/// A node in the flow graph
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
enum FlowGraphNode {
    Function(FunctionInst),
    Datatype(DatatypeItem),
}

/// An edge in the flow graph
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
enum FlowGraphEdge {
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
    Copy,
    Deref,
    Freeze,
    ImmBorrow,
    MutBorrow,
}

/// A database that holds information we can statically get from the packages
#[derive(Clone)]
pub struct FlowGraph<'a> {
    model: &'a Model,
    graph: DiGraph<FlowGraphNode, FlowGraphEdge>,
    next_type_param_index: usize,
}

impl<'a> FlowGraph<'a> {
    /// Analyze the given declaration (this is the entrypoint from outside)
    pub fn analyze(model: &'a Model, decl: &FunctionDecl, type_args: &[TypeBase]) -> Vec<Self> {
        let mut trace = vec![];
        let feasible_graphs =
            FlowGraph::new(model, type_args.len()).add_call(&mut trace, decl, type_args);
        assert!(trace.is_empty());
        feasible_graphs
    }

    /// Initialize the flow graph to an empty state
    fn new(model: &'a Model, next_type_param_index: usize) -> Self {
        Self {
            model,
            graph: DiGraph::new(),
            next_type_param_index,
        }
    }

    /// Add a call to a specific function instantiation into the graph
    fn add_call(
        mut self,
        trace: &mut Vec<FunctionInst>,
        decl: &FunctionDecl,
        type_args: &[TypeBase],
    ) -> Vec<Self> {
        // shortcut if we have reached max trace depth
        if trace.len() >= self.model.max_trace_depth {
            return vec![];
        }

        // check if we have seen this instantiation enough times
        let func_inst = FunctionInst {
            ident: decl.ident.clone(),
            type_args: type_args.to_vec(),
        };
        if trace.iter().filter(|f| *f == &func_inst).count() >= self.model.max_call_repetition {
            return vec![];
        }

        // now add this instantiation to the trace and a node to the graph
        trace.push(func_inst.clone());
        let call_node = self
            .graph
            .add_node(FlowGraphNode::Function(func_inst.clone()));

        // instantiate the function parameters
        let params_inst = decl
            .parameters
            .iter()
            .map(|t| {
                self.model
                    .datatype_registry
                    .instantiate_type_ref(t, type_args)
            })
            .collect_vec();

        // analyze the parameters
        let mut worklist = vec![];
        for (idx, ty) in params_inst.iter().enumerate() {
            let dt = match DatatypeItem::from_type_base(ty) {
                Some(item) => item,
                None => continue,
            };
            worklist.push((idx, dt));
        }

        let mut candidates = vec![self];
        for (idx, dt) in worklist {
            for graph in mem::take(&mut candidates) {
                let results = graph.add_arg(trace, call_node, idx, &dt);
                candidates.extend(results);
            }
        }

        // return all candidates
        let last_analyzed = trace.pop();
        assert_eq!(last_analyzed, Some(func_inst));
        candidates
    }

    /// Add an argument node to the graph
    fn add_arg(
        mut self,
        trace: &mut Vec<FunctionInst>,
        call_node: NodeIndex,
        arg_index: usize,
        arg_type: &DatatypeItem,
    ) -> Vec<Self> {
        // register a new node for this argument
        let arg_node = self
            .graph
            .add_node(FlowGraphNode::Datatype(arg_type.clone()));

        // add an edge from the argument node to the call
        self.graph
            .add_edge(arg_node, call_node, FlowGraphEdge::Use(arg_index));

        // construct the exploration plan based on the item type
        let mut stack = vec![];
        let candidates = self.plan_for_datatype(trace, &mut stack, arg_node);
        assert!(stack.is_empty());

        // done
        candidates
    }

    /// Plan for ways that a datatype can be provided
    fn plan_for_datatype(
        self,
        trace: &mut Vec<FunctionInst>,
        stack: &mut Vec<DatatypeItem>,
        dt_node: NodeIndex,
    ) -> Vec<Self> {
        // lookup the datatype item
        let dt_type = match self.graph.node_weight(dt_node).unwrap() {
            FlowGraphNode::Datatype(t) => t.clone(),
            _ => panic!("expected datatype node"),
        };

        // check if we have already planned for this datatype in the stack
        if stack.contains(&dt_type) {
            return vec![];
        }
        stack.push(dt_type.clone());

        // initialize the plan
        let mut plan = vec![];

        // construct the exploration plan based on the item type
        match &dt_type {
            DatatypeItem::Base(ty) => {
                let ty_base = ty.revert();

                // batch: deref
                if ty_base.abilities().has_copy() {
                    // batch: deref the imm ref
                    let mut new_graph = self.clone();
                    let src_type = DatatypeItem::ImmRef(ty.clone());
                    let src_node = new_graph.graph.add_node(FlowGraphNode::Datatype(src_type));
                    new_graph
                        .graph
                        .add_edge(src_node, dt_node, FlowGraphEdge::Deref);
                    plan.extend(new_graph.plan_for_datatype(trace, stack, src_node));

                    // batch: deref the mut ref
                    let mut new_graph = self.clone();
                    let src_type = DatatypeItem::MutRef(ty.clone());
                    let src_node = new_graph.graph.add_node(FlowGraphNode::Datatype(src_type));
                    new_graph
                        .graph
                        .add_edge(src_node, dt_node, FlowGraphEdge::Deref);
                    plan.extend(new_graph.plan_for_datatype(trace, stack, src_node));
                }

                // case analysis based on the complex type
                match ty {
                    ComplexType::Datatype { .. } => (), // no explicit plan for datatype
                    ComplexType::Param { .. } => (),    // no explicit plan for type parameter
                    ComplexType::Option { element } => {
                        let mut new_graph = self.clone();
                        let src_type = DatatypeItem::Base(element.as_ref().clone());
                        let src_node = new_graph.graph.add_node(FlowGraphNode::Datatype(src_type));
                        new_graph
                            .graph
                            .add_edge(src_node, dt_node, FlowGraphEdge::ElementToOption);
                        plan.extend(new_graph.plan_for_datatype(trace, stack, src_node));
                    },
                    ComplexType::Vector { variant, element } => {
                        let mut new_graph = self.clone();
                        let src_type = DatatypeItem::Base(element.as_ref().clone());
                        let src_node = new_graph.graph.add_node(FlowGraphNode::Datatype(src_type));
                        new_graph.graph.add_edge(
                            src_node,
                            dt_node,
                            FlowGraphEdge::ElementToVector { variant: *variant },
                        );
                        plan.extend(new_graph.plan_for_datatype(trace, stack, src_node));
                    },
                    ComplexType::MapOnKey {
                        key,
                        value,
                        variant,
                    } => {
                        let mut new_graph = self.clone();
                        let src_type = DatatypeItem::Base(key.as_ref().clone());
                        let src_node = new_graph.graph.add_node(FlowGraphNode::Datatype(src_type));
                        new_graph.graph.add_edge(
                            src_node,
                            dt_node,
                            FlowGraphEdge::KeyToMapSimple {
                                value: value.clone(),
                                variant: *variant,
                            },
                        );
                        plan.extend(new_graph.plan_for_datatype(trace, stack, src_node));
                    },
                    ComplexType::MapOnValue {
                        key,
                        value,
                        variant,
                    } => {
                        let mut new_graph = self.clone();
                        let src_type = DatatypeItem::Base(value.as_ref().clone());
                        let src_node = new_graph.graph.add_node(FlowGraphNode::Datatype(src_type));
                        new_graph.graph.add_edge(
                            src_node,
                            dt_node,
                            FlowGraphEdge::ValueToMapSimple {
                                key: key.clone(),
                                variant: *variant,
                            },
                        );
                        plan.extend(new_graph.plan_for_datatype(trace, stack, src_node));
                    },
                    ComplexType::MapOnBoth {
                        key,
                        value,
                        variant,
                    } => {
                        let mut new_graph = self.clone();

                        // nodes
                        let key_src_type = DatatypeItem::Base(key.as_ref().clone());
                        let key_src_node = new_graph
                            .graph
                            .add_node(FlowGraphNode::Datatype(key_src_type));

                        let val_src_type = DatatypeItem::Base(value.as_ref().clone());
                        let val_src_node = new_graph
                            .graph
                            .add_node(FlowGraphNode::Datatype(val_src_type));

                        // edges
                        new_graph.graph.add_edge(
                            key_src_node,
                            dt_node,
                            FlowGraphEdge::KeyToMapComplex {
                                value: val_src_node,
                                variant: *variant,
                            },
                        );
                        new_graph.graph.add_edge(
                            val_src_node,
                            dt_node,
                            FlowGraphEdge::ValueToMapComplex {
                                key: key_src_node,
                                variant: *variant,
                            },
                        );

                        // key side plans
                        let partial_plans = new_graph.plan_for_datatype(trace, stack, key_src_node);

                        // value side plans per each key side plan
                        for partial_graph in partial_plans {
                            plan.extend(partial_graph.plan_for_datatype(
                                trace,
                                stack,
                                val_src_node,
                            ));
                        }
                    },
                }
            },
            DatatypeItem::ImmRef(inner) => {
                // batch: freeze
                let mut new_graph = self.clone();
                let src_type = DatatypeItem::MutRef(inner.clone());
                let src_node = new_graph.graph.add_node(FlowGraphNode::Datatype(src_type));
                new_graph
                    .graph
                    .add_edge(src_node, dt_node, FlowGraphEdge::Freeze);
                plan.extend(new_graph.plan_for_datatype(trace, stack, src_node));

                // batch: imm borrow
                let mut new_graph = self.clone();
                let src_type = DatatypeItem::Base(inner.clone());
                let src_node = new_graph.graph.add_node(FlowGraphNode::Datatype(src_type));
                new_graph
                    .graph
                    .add_edge(src_node, dt_node, FlowGraphEdge::ImmBorrow);
                plan.extend(new_graph.plan_for_datatype(trace, stack, src_node));
            },
            DatatypeItem::MutRef(inner) => {
                // batch: mut borrow
                let mut new_graph = self.clone();
                let src_type = DatatypeItem::Base(inner.clone());
                let src_node = new_graph.graph.add_node(FlowGraphNode::Datatype(src_type));
                new_graph
                    .graph
                    .add_edge(src_node, dt_node, FlowGraphEdge::MutBorrow);
                plan.extend(new_graph.plan_for_datatype(trace, stack, src_node));
            },
        }

        // solve for providers
        plan.extend(self.probe_datatype_providers(trace, dt_node, &dt_type));

        // done
        let last_analyzed = stack.pop();
        assert_eq!(last_analyzed, Some(dt_type));
        plan
    }

    /// Probe for potential providers for a given datatype
    fn probe_datatype_providers(
        self,
        trace: &mut Vec<FunctionInst>,
        dt_node: NodeIndex,
        dt_type: &DatatypeItem,
    ) -> Vec<Self> {
        // sanity check
        assert!(!is_cyclic_directed(&self.graph));

        // ways of providing the datatype
        let mut candidates = vec![];
        candidates.extend(self.probe_internal(dt_node, dt_type));
        candidates.extend(self.probe_external(trace, dt_node, dt_type));
        candidates
    }

    /// Probe functions already registered in the graph for potential providers
    fn probe_internal(&self, target_node: NodeIndex, target_type: &DatatypeItem) -> Vec<Self> {
        let mut candidates = vec![];
        for node in self.graph.node_indices() {
            let func_inst = match self.graph.node_weight(node).unwrap() {
                FlowGraphNode::Datatype(_) => continue,
                FlowGraphNode::Function(f) => f,
            };

            // only check internal function when it does not create a loop in the graph
            let mut trial = self.graph.clone();
            trial.add_edge(
                node,
                target_node,
                FlowGraphEdge::Def(0), // dummy value as a placeholder
            );
            if is_cyclic_directed(&trial) {
                continue;
            }

            // check outgoing edges for unused return values
            let mut used_returns = BTreeSet::new();
            for edge in self.graph.edges_directed(node, Direction::Outgoing) {
                match edge.weight() {
                    FlowGraphEdge::Def(idx) => {
                        let inserted = used_returns.insert(*idx);
                        assert!(inserted);
                    },
                    _ => panic!("unexpected outgoing edge from function node"),
                }
            }

            // try to unify the return type with the target datatype
            let func_decl = self.model.function_registry.lookup_decl(&func_inst.ident);
            for (idx, ty_base) in func_decl.return_sig.iter().enumerate() {
                if used_returns.contains(&idx) {
                    continue;
                }

                // probe for datatype
                let ty_item = self
                    .model
                    .datatype_registry
                    .instantiate_type_ref(ty_base, &func_inst.type_args);
                let dt_item = match DatatypeItem::from_type_base(&ty_item) {
                    Some(item) => item,
                    None => continue,
                };

                // check for match
                // NOTE: it seems that we only need to care for exact match here instead of
                // subtyping or type unification. They should be handled separately.
                if target_type != &dt_item {
                    continue;
                }

                // found a candidate
                let mut new_graph = self.clone();
                new_graph
                    .graph
                    .add_edge(node, target_node, FlowGraphEdge::Def(idx));
                candidates.push(new_graph);
            }
        }
        candidates
    }

    /// Bring new functions from the model to provide the target datatype
    fn probe_external(
        &self,
        trace: &mut Vec<FunctionInst>,
        target_node: NodeIndex,
        target_type: &DatatypeItem,
    ) -> Vec<Self> {
        todo!()
    }
}
