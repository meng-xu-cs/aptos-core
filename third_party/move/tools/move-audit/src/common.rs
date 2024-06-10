use crate::deps::PkgManifest;
use anyhow::bail;
use aptos_crypto::{ed25519::Ed25519PrivateKey, PrivateKey};
use aptos_framework::extended_checks;
use aptos_types::transaction::authenticator::AuthenticationKey;
use move_binary_format::file_format_common;
use move_core_types::account_address::AccountAddress;
use move_model::metadata::{CompilerVersion, LanguageVersion};
use move_package::CompilerConfig;
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

/// A Move audit project composed by a list of packages to audit
pub struct Project {
    pub pkgs: Vec<(PkgManifest, bool)>,
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
            }),
            bytecode_version: Some(match version {
                LanguageVersion::V1 => file_format_common::VERSION_6,
                LanguageVersion::V2_0 => file_format_common::VERSION_7,
                LanguageVersion::V2_1 => file_format_common::VERSION_8,
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
        };
        match optimization {
            OptLevel::Default => command.args(["--optimize", "default"]),
            OptLevel::None => command.args(["--optimize", "none"]),
            OptLevel::Extra => command.args(["--optimize", "extra"]),
        };
    }
}
