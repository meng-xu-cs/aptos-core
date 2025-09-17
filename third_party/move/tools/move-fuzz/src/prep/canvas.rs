// Copyright (c) Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::prep::{
    ident::{DatatypeIdent, FunctionIdent},
    typing::{MapVariant, SimpleType, TypeBase, VectorVariant},
};
use move_core_types::ability::AbilitySet;

/// Types that can be argument of driver function
#[derive(Debug, Clone)]
pub enum BasicInput {
    Bool,
    U8,
    I8,
    U16,
    I16,
    U32,
    I32,
    U64,
    I64,
    U128,
    I128,
    U256,
    I256,
    String,
    Address,
    Signer,
    Vector(Box<Self>),
}

impl BasicInput {
    pub fn with_depth(self, depth: usize) -> Self {
        assert!(!matches!(self, Self::Vector(_)));
        if depth == 0 {
            return self;
        }
        Self::Vector(self.with_depth(depth - 1).into())
    }
}

#[derive(Debug, Copy, Clone)]
pub enum DriverVariable {
    Param(usize),
    Local(usize),
}

#[derive(Debug, Clone)]
pub enum DriverStatement {
    Call {
        ident: FunctionIdent,
        type_args: Vec<TypeBase>,
        arguments: Vec<DriverVariable>,
        ret_binds: Vec<Option<usize>>,
    },
    ImmBorrow {
        src: DriverVariable,
        dst: usize,
    },
    MutBorrow {
        src: DriverVariable,
        dst: usize,
    },
    Deref {
        src: DriverVariable,
        dst: usize,
    },

    // the following is only expected to be used as argument bridges
    Arg2Bitvec {
        src: DriverVariable,
        depth: usize,
        dst: usize,
    },
    Arg2SmartVec {
        src: DriverVariable,
        depth: usize,
        dst: usize,
    },
    Arg2Map {
        src_key: DriverVariable,
        src_value: DriverVariable,
        depth: usize,
        variant: MapVariant,
        dst: usize,
    },
    Arg2ObjectKnown {
        src: DriverVariable,
        ident: DatatypeIdent,
        type_args: Vec<TypeBase>,
        depth: usize,
        dst: usize,
    },
    Arg2ObjectParam {
        src: DriverVariable,
        param: usize,
        depth: usize,
        dst: usize,
    },
}

/// A data structure that holds the details on how to generate a driver
#[derive(Debug, Clone)]
pub struct DriverCanvas {
    generics: Vec<AbilitySet>,
    parameters: Vec<BasicInput>,
    statements: Vec<DriverStatement>,
    local_var_count: usize,
}

impl DriverCanvas {
    /// Create a new canvas
    pub fn new() -> Self {
        Self {
            generics: vec![],
            parameters: vec![],
            statements: vec![],
            local_var_count: 0,
        }
    }

    /// Add a new generic type parameter
    fn new_param(&mut self, constraints: AbilitySet) -> usize {
        let index = self.generics.len();
        self.generics.push(constraints);
        index
    }

    /// Add a new input
    fn new_input(&mut self, base: BasicInput, depth: usize) -> DriverVariable {
        let index = self.parameters.len();
        self.parameters.push(base.with_depth(depth));
        DriverVariable::Param(index)
    }

    /// Create a new index for a local variable
    fn new_local(&mut self) -> usize {
        let index = self.local_var_count;
        self.local_var_count += 1;
        index
    }

    /// Register parameters for an input type
    fn add_input_simple_recursive(&mut self, t: &SimpleType, depth: usize) -> DriverVariable {
        match t {
            SimpleType::Bool => self.new_input(BasicInput::Bool, depth),
            SimpleType::U8 => self.new_input(BasicInput::U8, depth),
            SimpleType::I8 => self.new_input(BasicInput::I8, depth),
            SimpleType::U16 => self.new_input(BasicInput::U16, depth),
            SimpleType::I16 => self.new_input(BasicInput::I16, depth),
            SimpleType::U32 => self.new_input(BasicInput::U32, depth),
            SimpleType::I32 => self.new_input(BasicInput::I32, depth),
            SimpleType::U64 => self.new_input(BasicInput::U64, depth),
            SimpleType::I64 => self.new_input(BasicInput::I64, depth),
            SimpleType::U128 => self.new_input(BasicInput::U128, depth),
            SimpleType::I128 => self.new_input(BasicInput::I128, depth),
            SimpleType::U256 => self.new_input(BasicInput::U256, depth),
            SimpleType::I256 => self.new_input(BasicInput::I256, depth),
            SimpleType::Bitvec => {
                let src = self.new_input(BasicInput::Bool, depth + 1);
                let dst = self.new_local();
                self.statements
                    .push(DriverStatement::Arg2Bitvec { src, depth, dst });
                DriverVariable::Local(dst)
            },
            SimpleType::String => self.new_input(BasicInput::String, depth),
            SimpleType::Address => self.new_input(BasicInput::Address, depth),
            SimpleType::Signer => self.new_input(BasicInput::Signer, depth),
            SimpleType::Option { element: _ } => todo!("optional argument is not supported yet"),
            SimpleType::Vector { element, variant } => match variant {
                VectorVariant::Vector => self.add_input_simple_recursive(element, depth + 1),
                VectorVariant::BigVector => panic!("there is no way to construct a BigVector"),
                VectorVariant::SmartVector => {
                    let src = self.add_input_simple_recursive(element, depth + 1);
                    let dst = self.new_local();
                    self.statements
                        .push(DriverStatement::Arg2SmartVec { src, depth, dst });
                    DriverVariable::Local(dst)
                },
            },
            SimpleType::Map {
                key,
                value,
                variant,
            } => {
                let src_key = self.add_input_simple_recursive(key, depth + 1);
                let src_value = self.add_input_simple_recursive(value, depth + 1);
                let dst = self.new_local();
                self.statements.push(DriverStatement::Arg2Map {
                    src_key,
                    src_value,
                    depth,
                    variant: *variant,
                    dst,
                });
                DriverVariable::Local(dst)
            },
            SimpleType::ObjectKnown {
                ident,
                type_args,
                abilities: _,
            } => {
                let src = self.new_input(BasicInput::Address, depth);
                let dst = self.new_local();
                self.statements.push(DriverStatement::Arg2ObjectKnown {
                    src,
                    ident: ident.clone(),
                    type_args: type_args.clone(),
                    depth,
                    dst,
                });
                DriverVariable::Local(dst)
            },
            SimpleType::ObjectParam {
                index: param,
                abilities: _,
            } => {
                let src = self.new_input(BasicInput::Address, depth);
                let dst = self.new_local();
                self.statements.push(DriverStatement::Arg2ObjectParam {
                    src,
                    param: *param,
                    depth,
                    dst,
                });
                DriverVariable::Local(dst)
            },
        }
    }

    /// Create an immutable borrow statement
    pub fn new_stmt_imm_borrow(&mut self, src: DriverVariable) -> DriverVariable {
        let dst_index = self.new_local();
        self.statements.push(DriverStatement::ImmBorrow {
            src,
            dst: dst_index,
        });
        DriverVariable::Local(dst_index)
    }

    /// Create a mutable borrow statement
    pub fn new_stmt_mut_borrow(&mut self, src: DriverVariable) -> DriverVariable {
        let dst_index = self.new_local();
        self.statements.push(DriverStatement::MutBorrow {
            src,
            dst: dst_index,
        });
        DriverVariable::Local(dst_index)
    }
}
