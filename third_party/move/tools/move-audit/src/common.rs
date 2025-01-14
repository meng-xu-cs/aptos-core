use crate::deps::PkgManifest;
use anyhow::{bail, Result};
use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey};
use aptos_framework::extended_checks;
use aptos_types::transaction::authenticator::AuthenticationKey;
use move_binary_format::{
    binary_views::BinaryIndexedView,
    file_format::{AbilitySet, SignatureToken},
    file_format_common,
};
use move_core_types::{account_address::AccountAddress, u256};
use move_model::metadata::{CompilerVersion, LanguageVersion};
use move_package::{compilation::compiled_package::CompiledPackage, CompilerConfig};
use std::{collections::BTreeMap, process::Command, str::FromStr};

/// Account (either referenced or owned)
pub enum Account {
    Ref(AccountAddress),
    Owned(Ed25519PrivateKey),
}

impl Account {
    pub fn address(&self) -> AccountAddress {
        match self {
            Self::Ref(addr) => *addr,
            Self::Owned(key) => AuthenticationKey::ed25519(&key.public_key()).account_address(),
        }
    }
}

/// Supported transaction argument types
#[derive(Clone)]
pub enum TxnArgType {
    Bool,
    U8,
    U16,
    U32,
    U64,
    U128,
    U256,
    Address,
    Signer,
    String,
    Vector(Box<TxnArgType>),
}

impl TxnArgType {
    pub fn convert(binary: BinaryIndexedView, token: &SignatureToken) -> Result<Self> {
        let converted = match token {
            SignatureToken::Bool => Self::Bool,
            SignatureToken::U8 => Self::U8,
            SignatureToken::U16 => Self::U16,
            SignatureToken::U32 => Self::U32,
            SignatureToken::U64 => Self::U64,
            SignatureToken::U128 => Self::U128,
            SignatureToken::U256 => Self::U256,
            SignatureToken::Address => Self::Address,
            SignatureToken::Signer => Self::Signer,
            SignatureToken::Struct(idx) => {
                let struct_handle = binary.struct_handle_at(*idx);
                let module_handle = binary.module_handle_at(struct_handle.module);
                if binary.identifier_at(struct_handle.name).as_str() == "String"
                    && binary.identifier_at(module_handle.name).as_str() == "string"
                    && binary.address_identifier_at(module_handle.address) == &AccountAddress::ONE
                {
                    Self::String
                } else {
                    bail!("unexpected struct in function signature");
                }
            },
            SignatureToken::Reference(sub) => {
                if matches!(sub.as_ref(), SignatureToken::Signer) {
                    Self::Signer
                } else {
                    bail!("unexpected reference in function signature");
                }
            },
            SignatureToken::Vector(sub) => Self::Vector(Self::convert(binary, sub)?.into()),
            _ => bail!("unexpected type in function signature"),
        };
        Ok(converted)
    }

    pub fn type_mark(&self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::U128 => "u128",
            Self::U256 => "u256",
            Self::Address => "address",
            Self::Signer => "signer",
            Self::String => "string",
            Self::Vector(sub) => sub.type_mark(),
        }
    }

    pub fn type_name(&self) -> String {
        match self {
            Self::Bool => "bool".to_string(),
            Self::U8 => "u8".to_string(),
            Self::U16 => "u16".to_string(),
            Self::U32 => "u32".to_string(),
            Self::U64 => "u64".to_string(),
            Self::U128 => "u128".to_string(),
            Self::U256 => "u256".to_string(),
            Self::Address => "address".to_string(),
            Self::Signer => "signer".to_string(),
            Self::String => "std::string::String".to_string(),
            Self::Vector(sub) => format!("vector<{}>", sub.type_name()),
        }
    }
}

/// Supported transaction argument
pub enum TxnArg {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),
    U256(u256::U256),
    Address(AccountAddress),
    Signer(AccountAddress),
    String(String),
    Vector(TxnArgType, Vec<TxnArg>),
}

impl TxnArg {
    pub fn to_cli_string(&self) -> String {
        match self {
            Self::Bool(b) => b.to_string(),
            Self::U8(n) => n.to_string(),
            Self::U16(n) => n.to_string(),
            Self::U32(n) => n.to_string(),
            Self::U64(n) => n.to_string(),
            Self::U128(n) => n.to_string(),
            Self::U256(n) => n.to_string(),
            Self::Address(a) => a.to_standard_string(),
            Self::Signer(a) => a.to_standard_string(),
            Self::String(s) => s.clone(),
            Self::Vector(_, sub) => {
                format!(
                    "[{}]",
                    sub.iter()
                        .map(|arg| arg.to_cli_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            },
        }
    }
}

/// Supported API (a.k.a., public function) argument types
#[derive(Clone)]
pub enum TxnArgTypeWithRef {
    Base(TxnArgType),
    RefImm(TxnArgType),
    RefMut(TxnArgType),
}

impl TxnArgTypeWithRef {
    pub fn convert(binary: BinaryIndexedView, token: &SignatureToken) -> Result<Self> {
        let converted = match token {
            SignatureToken::Reference(sub) => {
                Self::RefImm(TxnArgType::convert(binary, sub.as_ref())?)
            },
            SignatureToken::MutableReference(sub) => {
                Self::RefMut(TxnArgType::convert(binary, sub.as_ref())?)
            },
            _ => Self::Base(TxnArgType::convert(binary, token)?),
        };
        Ok(converted)
    }

    pub fn reduce(&self) -> TxnArgType {
        match self {
            Self::Base(ty) | Self::RefImm(ty) | Self::RefMut(ty) => ty.clone(),
        }
    }

    pub fn is_droppable(
        binary: BinaryIndexedView,
        generics: &[AbilitySet],
        token: &SignatureToken,
    ) -> bool {
        match token {
            SignatureToken::Bool
            | SignatureToken::U8
            | SignatureToken::U16
            | SignatureToken::U32
            | SignatureToken::U64
            | SignatureToken::U128
            | SignatureToken::U256
            | SignatureToken::Address
            | SignatureToken::Signer
            | SignatureToken::Reference(_)
            | SignatureToken::MutableReference(_) => true,
            SignatureToken::Struct(idx) | SignatureToken::StructInstantiation(idx, _) => {
                let handle = binary.struct_handle_at(*idx);
                handle.abilities.has_drop()
            },
            SignatureToken::Vector(sub) => Self::is_droppable(binary, generics, sub.as_ref()),
            SignatureToken::TypeParameter(idx) => generics
                .get(*idx as usize)
                .expect("type parameter")
                .has_drop(),
        }
    }
}

/// A wrapper over package manifest that also marks what kind of package this is
pub enum PkgDeclaration {
    /// primary package to be analyzed
    Primary(PkgManifest),
    /// a direct or transitive dependency of a primary package
    Dependency(PkgManifest),
    /// a dependency that is also part of the Aptos Framework
    Framework(PkgManifest),
}

impl PkgDeclaration {
    pub fn as_manifest(&self) -> &PkgManifest {
        match self {
            Self::Primary(manifest) | Self::Dependency(manifest) | Self::Framework(manifest) => {
                manifest
            },
        }
    }
}

/// A Move audit project composed by a list of packages to audit
pub struct Project {
    pub pkgs: Vec<PkgDeclaration>,
    pub named_accounts: BTreeMap<String, Account>,
    pub language: LanguageSetting,
}

/// Optimization level during the compilation
#[derive(Copy, Clone)]
pub enum OptLevel {
    /// Default optimization level
    Default,
    /// No optimizations
    None,
    /// Extra optimizations, that may take more time
    Extra,
}

/// Move compilation specification
#[derive(Copy, Clone)]
pub struct LanguageSetting {
    pub version: LanguageVersion,
    pub optimization: OptLevel,
}

impl FromStr for LanguageSetting {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (optimization, rest) = match s.strip_suffix('-') {
            None => match s.strip_suffix('+') {
                None => (OptLevel::Default, s),
                Some(r) => (OptLevel::Extra, r),
            },
            Some(r) => (OptLevel::None, r),
        };
        let version = LanguageVersion::from_str(rest)?;

        // sanity check
        if matches!(version, LanguageVersion::V1) && !matches!(optimization, OptLevel::Default) {
            bail!("V1 of the language does not support optimization");
        }

        // done
        Ok(LanguageSetting {
            version,
            optimization,
        })
    }
}

impl LanguageSetting {
    /// Derive a suitable `CompilerConfig` based on the language setting
    pub fn derive_compilation_config(&self) -> CompilerConfig {
        let Self {
            version,
            optimization,
        } = self;

        let mut experiments = vec![];
        if !matches!(version, LanguageVersion::V1) {
            match optimization {
                OptLevel::Default => {
                    experiments.push("optimize=on".to_string());
                },
                OptLevel::None => {
                    experiments.push("optimize=off".to_string());
                },
                OptLevel::Extra => {
                    experiments.push("optimize=on".to_string());
                    experiments.push("optimize-extra=on".to_string());
                },
            }
        }

        // TODO(mengxu): keep in sync with `aptos_framework::build_package::BuildOptions::move_2()`
        CompilerConfig {
            known_attributes: extended_checks::get_all_attribute_names().clone(),
            skip_attribute_checks: false,
            language_version: Some(*version),
            compiler_version: Some(match version {
                LanguageVersion::V1 => CompilerVersion::V1,
                LanguageVersion::V2_0 => CompilerVersion::V2_0,
                LanguageVersion::V2_1 => CompilerVersion::V2_1,
                LanguageVersion::V2_2 => CompilerVersion::V2_1,
            }),
            bytecode_version: Some(match version {
                LanguageVersion::V1 => file_format_common::VERSION_6,
                LanguageVersion::V2_0 => file_format_common::VERSION_7,
                LanguageVersion::V2_1 => file_format_common::VERSION_7,
                LanguageVersion::V2_2 => file_format_common::VERSION_8,
            }),
            experiments,
        }
    }

    /// Derive the suitable CLI options based on the language setting
    pub fn derive_cli_options(&self, command: &mut Command) {
        let Self {
            version,
            optimization,
        } = self;

        // TODO(mengxu): keep in sync with `aptos_framework::build_package::BuildOptions::move_2()`
        match version {
            LanguageVersion::V1 => command.args([
                "--language-version",
                "1",
                "--compiler-version",
                "1",
                "--bytecode-version",
                "6",
            ]),
            LanguageVersion::V2_0 => command.args([
                "--language-version",
                "2.0",
                "--compiler-version",
                "2.0",
                "--bytecode-version",
                "7",
            ]),
            LanguageVersion::V2_1 => command.args([
                "--language-version",
                "2.1",
                "--compiler-version",
                "2.1",
                "--bytecode-version",
                "7",
            ]),
            LanguageVersion::V2_2 => command.args([
                "--language-version",
                "2.2",
                "--compiler-version",
                "2.1",
                "--bytecode-version",
                "8",
            ]),
        };
        match optimization {
            OptLevel::Default => command.args(["--optimize", "default"]),
            OptLevel::None => command.args(["--optimize", "none"]),
            OptLevel::Extra => command.args(["--optimize", "extra"]),
        };
    }
}

/// A wrapper over CompiledPackage that also marks what kind of package this is
pub enum PkgDefinition {
    /// primary package to be analyzed
    Primary(CompiledPackage),
    /// a direct or transitive dependency of a primary package
    Dependency(CompiledPackage),
    /// a dependency that is also part of the Aptos Framework
    Framework(CompiledPackage),
}

impl PkgDefinition {
    pub fn as_compiled_package(&self) -> &CompiledPackage {
        match self {
            Self::Primary(compiled) | Self::Dependency(compiled) | Self::Framework(compiled) => {
                compiled
            },
        }
    }
}
