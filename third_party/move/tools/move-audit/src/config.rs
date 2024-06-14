use lazy_static::lazy_static;
use std::{path::PathBuf, process::Command};

lazy_static! {
    /// Path to the freshly built Aptos CLI (only works in debug mode)
    pub static ref APTOS_BIN: PathBuf = {
        let stdout = Command::new(env!("CARGO"))
            .arg("locate-project")
            .arg("--workspace")
            .arg("--message-format=plain")
            .output()
            .expect("workspace located")
            .stdout;
        let output = String::from_utf8(stdout).expect("utf-8");

        let mut path = PathBuf::from(output.trim());
        assert!(path.pop());
        path.push("target");
        path.push("debug");
        path.push("aptos");
        path
    };
}
