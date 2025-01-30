use crate::fuzz::{
    entrypoint::{FunctionDecl, FunctionRegistry},
    ident::{DatatypeIdent, FunctionIdent},
    typing::{
        DatatypeRegistry, MapVariant, TypeBase, TypeItem, TypeRef, TypeTag, TypeUnifier,
        VectorVariant,
    },
};
use itertools::Itertools;
use move_core_types::ability::AbilitySet;
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

/// Types that can be trivially constructed and destructed
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum SimpleType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Bitvec,
    String,
    Address,
    Signer,
    Vector {
        element: Box<Self>,
        variant: VectorVariant,
    },
    Map {
        key: Box<Self>,
        value: Box<Self>,
        variant: MapVariant,
    },
    Object {
        ident: DatatypeIdent,
        type_args: Vec<TypeBase>,
        abilities: AbilitySet,
    },
}

impl From<SimpleType> for TypeBase {
    fn from(t: SimpleType) -> TypeBase {
        match t {
            SimpleType::Bool => TypeBase::Bool,
            SimpleType::U8 => TypeBase::U8,
            SimpleType::U16 => TypeBase::U16,
            SimpleType::U32 => TypeBase::U32,
            SimpleType::U64 => TypeBase::U64,
            SimpleType::U128 => TypeBase::U128,
            SimpleType::U256 => TypeBase::U256,
            SimpleType::Bitvec => TypeBase::Bitvec,
            SimpleType::String => TypeBase::String,
            SimpleType::Address => TypeBase::Address,
            SimpleType::Signer => TypeBase::Signer,
            SimpleType::Vector { element, variant } => TypeBase::Vector {
                element: Box::new((*element).into()),
                variant,
            },
            SimpleType::Map {
                key,
                value,
                variant,
            } => TypeBase::Map {
                key: Box::new((*key).into()),
                value: Box::new((*value).into()),
                variant,
            },
            SimpleType::Object {
                ident,
                type_args,
                abilities,
            } => TypeBase::Object {
                ident,
                type_args,
                abilities,
            },
        }
    }
}

/// A type closure constructed based on datatypes (cannot be trivially handled)
#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum ComplexType {
    Unit {
        ident: DatatypeIdent,
        type_args: Vec<TypeBase>,
        abilities: AbilitySet,
    },
    Vector {
        element: Box<Self>,
        variant: VectorVariant,
    },
    MapOnKey {
        key: Box<Self>,
        value: SimpleType,
        variant: MapVariant,
    },
    MapOnValue {
        key: SimpleType,
        value: Box<Self>,
        variant: MapVariant,
    },
    MapOnBoth {
        key: Box<Self>,
        value: Box<Self>,
        variant: MapVariant,
    },
}

impl From<ComplexType> for TypeBase {
    fn from(t: ComplexType) -> TypeBase {
        match t {
            ComplexType::Unit {
                ident,
                type_args,
                abilities,
            } => TypeBase::Datatype {
                ident,
                type_args,
                abilities,
            },
            ComplexType::Vector { element, variant } => TypeBase::Vector {
                element: Box::new((*element).into()),
                variant,
            },
            ComplexType::MapOnKey {
                key,
                value,
                variant,
            } => TypeBase::Map {
                key: Box::new((*key).into()),
                value: Box::new(value.into()),
                variant,
            },
            ComplexType::MapOnValue {
                key,
                value,
                variant,
            } => TypeBase::Map {
                key: Box::new(key.into()),
                value: Box::new((*value).into()),
                variant,
            },
            ComplexType::MapOnBoth {
                key,
                value,
                variant,
            } => TypeBase::Map {
                key: Box::new((*key).into()),
                value: Box::new((*value).into()),
                variant,
            },
        }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeClosureBase {
    Simple(SimpleType),
    Complex(ComplexType),
}

impl From<TypeBase> for TypeClosureBase {
    fn from(t: TypeBase) -> TypeClosureBase {
        match t {
            TypeBase::Bool => TypeClosureBase::Simple(SimpleType::Bool),
            TypeBase::U8 => TypeClosureBase::Simple(SimpleType::U8),
            TypeBase::U16 => TypeClosureBase::Simple(SimpleType::U16),
            TypeBase::U32 => TypeClosureBase::Simple(SimpleType::U32),
            TypeBase::U64 => TypeClosureBase::Simple(SimpleType::U64),
            TypeBase::U128 => TypeClosureBase::Simple(SimpleType::U128),
            TypeBase::U256 => TypeClosureBase::Simple(SimpleType::U256),
            TypeBase::Bitvec => TypeClosureBase::Simple(SimpleType::Bitvec),
            TypeBase::String => TypeClosureBase::Simple(SimpleType::String),
            TypeBase::Address => TypeClosureBase::Simple(SimpleType::Address),
            TypeBase::Signer => TypeClosureBase::Simple(SimpleType::Signer),
            TypeBase::Vector { element, variant } => match TypeClosureBase::from(*element) {
                TypeClosureBase::Simple(simple_element) => {
                    TypeClosureBase::Simple(SimpleType::Vector {
                        element: simple_element.into(),
                        variant,
                    })
                },
                TypeClosureBase::Complex(complex_element) => {
                    TypeClosureBase::Complex(ComplexType::Vector {
                        element: complex_element.into(),
                        variant,
                    })
                },
            },
            TypeBase::Map {
                key,
                value,
                variant,
            } => match (TypeClosureBase::from(*key), TypeClosureBase::from(*value)) {
                (TypeClosureBase::Simple(simple_key), TypeClosureBase::Simple(simple_value)) => {
                    TypeClosureBase::Simple(SimpleType::Map {
                        key: simple_key.into(),
                        value: simple_value.into(),
                        variant,
                    })
                },
                (TypeClosureBase::Simple(simple_key), TypeClosureBase::Complex(complex_value)) => {
                    TypeClosureBase::Complex(ComplexType::MapOnValue {
                        key: simple_key,
                        value: complex_value.into(),
                        variant,
                    })
                },
                (TypeClosureBase::Complex(complex_key), TypeClosureBase::Simple(simple_value)) => {
                    TypeClosureBase::Complex(ComplexType::MapOnKey {
                        key: complex_key.into(),
                        value: simple_value,
                        variant,
                    })
                },
                (
                    TypeClosureBase::Complex(complex_key),
                    TypeClosureBase::Complex(complex_value),
                ) => TypeClosureBase::Complex(ComplexType::MapOnBoth {
                    key: complex_key.into(),
                    value: complex_value.into(),
                    variant,
                }),
            },
            TypeBase::Datatype {
                ident,
                type_args,
                abilities,
            } => TypeClosureBase::Complex(ComplexType::Unit {
                ident,
                type_args,
                abilities,
            }),
            TypeBase::Object {
                ident,
                type_args,
                abilities,
            } => TypeClosureBase::Simple(SimpleType::Object {
                ident,
                type_args,
                abilities,
            }),
        }
    }
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum TypeClosureItem {
    Base(TypeClosureBase),
    ImmRef(TypeClosureBase),
    MutRef(TypeClosureBase),
}

impl From<TypeItem> for TypeClosureItem {
    fn from(t: TypeItem) -> TypeClosureItem {
        match t {
            TypeItem::Base(base) => TypeClosureItem::Base(base.into()),
            TypeItem::ImmRef(base) => TypeClosureItem::ImmRef(base.into()),
            TypeItem::MutRef(base) => TypeClosureItem::MutRef(base.into()),
        }
    }
}

/// Types that can be argument of driver function
#[derive(Debug, Clone)]
pub enum BasicType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    String,
    Address,
    Signer,
    Vector(Box<Self>),
}

impl BasicType {
    pub fn with_depth(self, depth: usize) -> Self {
        assert!(!matches!(self, Self::Vector(_)));
        if depth == 0 {
            return self;
        }
        Self::Vector(self.with_depth(depth - 1).into())
    }
}

#[derive(Debug, Copy, Clone)]
enum DriverVariable {
    Param(usize),
    Local(usize),
}

#[derive(Debug, Clone)]
enum DriverStatement {
    Call {
        function: FunctionInst,
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
    Arg2Object {
        src: DriverVariable,
        ident: DatatypeIdent,
        type_args: Vec<TypeBase>,
        depth: usize,
        dst: usize,
    },
}

/// A data structure that holds the details on how to generate a driver
#[derive(Debug, Clone)]
struct DriverCanvas {
    parameters: Vec<BasicType>,
    statements: Vec<DriverStatement>,
    local_var_count: usize,
}

impl DriverCanvas {
    /// Create a new index for a local variable
    fn new_local(&mut self) -> usize {
        let index = self.local_var_count;
        self.local_var_count += 1;
        index
    }

    /// Add a new param
    fn new_param(&mut self, base: BasicType, depth: usize) -> DriverVariable {
        let index = self.parameters.len();
        self.parameters.push(base.with_depth(depth));
        DriverVariable::Param(index)
    }

    /// Register parameters for an input type
    pub fn add_input_simple_recursive(&mut self, t: &SimpleType, depth: usize) -> DriverVariable {
        match t {
            SimpleType::Bool => self.new_param(BasicType::Bool, depth),
            SimpleType::U8 => self.new_param(BasicType::U8, depth),
            SimpleType::U16 => self.new_param(BasicType::U16, depth),
            SimpleType::U32 => self.new_param(BasicType::U32, depth),
            SimpleType::U64 => self.new_param(BasicType::U64, depth),
            SimpleType::U128 => self.new_param(BasicType::U128, depth),
            SimpleType::U256 => self.new_param(BasicType::U256, depth),
            SimpleType::Bitvec => {
                let param = self.new_param(BasicType::Bool, depth + 1);
                let dst_index = self.new_local();
                self.statements.push(DriverStatement::Arg2Bitvec {
                    src: param,
                    depth,
                    dst: dst_index,
                });
                DriverVariable::Local(dst_index)
            },
            SimpleType::String => self.new_param(BasicType::String, depth),
            SimpleType::Address => self.new_param(BasicType::Address, depth),
            SimpleType::Signer => self.new_param(BasicType::Signer, depth),
            SimpleType::Vector { element, variant } => match variant {
                VectorVariant::Vector => self.add_input_simple_recursive(element, depth + 1),
                VectorVariant::BigVector => panic!("there is no way to construct a BigVector"),
                VectorVariant::SmartVector => {
                    let var = self.add_input_simple_recursive(element, depth + 1);
                    let dst_index = self.new_local();
                    self.statements.push(DriverStatement::Arg2SmartVec {
                        src: var,
                        depth,
                        dst: dst_index,
                    });
                    DriverVariable::Local(dst_index)
                },
            },
            SimpleType::Map {
                key,
                value,
                variant,
            } => {
                let var_k = self.add_input_simple_recursive(key, depth + 1);
                let var_v = self.add_input_simple_recursive(value, depth + 1);
                let dst_index = self.new_local();
                self.statements.push(DriverStatement::Arg2Map {
                    src_key: var_k,
                    src_value: var_v,
                    depth,
                    variant: *variant,
                    dst: dst_index,
                });
                DriverVariable::Local(dst_index)
            },
            SimpleType::Object {
                ident,
                type_args,
                abilities: _,
            } => {
                let param = self.new_param(BasicType::Address, depth);
                let dst_index = self.new_local();
                self.statements.push(DriverStatement::Arg2Object {
                    src: param,
                    ident: ident.clone(),
                    type_args: type_args.clone(),
                    depth,
                    dst: dst_index,
                });
                DriverVariable::Local(dst_index)
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

/// A driver generator that also caches information during driver generation
pub struct DriverGenerator<'a> {
    // information registry
    datatype_registry: &'a DatatypeRegistry,
    function_registry: &'a FunctionRegistry,

    // configs
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

    /// Analyze the function instantiation and update the stateful variables
    fn analyze_function_inst(&mut self, decl: &FunctionDecl, inst: FunctionInst) {
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
        let mut canvas = DriverCanvas {
            parameters: vec![],
            statements: vec![],
            local_var_count: 0,
        };

        // prepare the arguments
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
                    // search for a provider
                    self.probe_providers_complex(t);

                    // TODO: if type is copy-able, we can also search for refs
                    log::info!("function {inst} requires {}", TypeBase::from(t.clone()));
                },
                TypeClosureItem::ImmRef(TypeClosureBase::Complex(t)) => {
                    // TODO
                    log::info!("function {inst} requires &{}", TypeBase::from(t.clone()));
                },
                TypeClosureItem::MutRef(TypeClosureBase::Complex(t)) => {
                    // TODO
                    log::info!(
                        "function {inst} requires &mut {}",
                        TypeBase::from(t.clone())
                    );
                },
            }
        }

        for (i, item) in ret_ty.iter().enumerate() {
            match item {
                TypeClosureItem::Base(TypeClosureBase::Simple(_))
                | TypeClosureItem::ImmRef(_)
                | TypeClosureItem::MutRef(_) => continue,
                TypeClosureItem::Base(TypeClosureBase::Complex(t)) => {
                    // TODO
                    let t = TypeBase::from(t.clone());
                    if t.abilities().has_drop() {
                        continue;
                    }
                    log::info!("function {inst} needs to deposit {t}",);
                },
            }
        }
    }

    fn probe_providers_complex(&mut self, datatype: &ComplexType) {
        // TODO: check if we have cached it
    }

    /// Generate drivers (zero to multiple) for an entrypoint declaration
    pub fn generate_drivers(&mut self, decl: &FunctionDecl) {
        // derive instantiations
        for inst in self.collect_function_insts(decl) {
            self.analyze_function_inst(decl, inst);
        }
    }
}
