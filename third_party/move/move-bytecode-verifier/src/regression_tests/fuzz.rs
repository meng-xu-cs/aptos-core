use move_binary_format::CompiledModule;
use move_core_types::vm_status::StatusCode;

use crate::verifier::verify_module;

#[test]
fn miri_path_fuzz() {
    let module = CompiledModule::default();
    match verify_module(&module) {
        Ok(_) => (),
        Err(e) => {
            let status = e.major_status();
            // additionally force a panic on status code that should not been reached
            match status {
                StatusCode::UNKNOWN_VALIDATION_STATUS => unreachable!("UNKNOWN_VALIDATION_STATUS"),
                StatusCode::UNKNOWN_VERIFICATION_ERROR => unreachable!("UNKNOWN_VERIFICATION_ERROR"),
                StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR => unreachable!("UNKNOWN_INVARIANT_VIOLATION_ERROR"),
                StatusCode::UNREACHABLE => unreachable!("UNREACHABLE"),
                StatusCode::UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION => unreachable!("UNEXPECTED_ERROR_FROM_KNOWN_MOVE_FUNCTION"),
                StatusCode::VERIFIER_INVARIANT_VIOLATION => unreachable!("VERIFIER_INVARIANT_VIOLATION"),
                StatusCode::UNEXPECTED_VERIFIER_ERROR => unreachable!("UNEXPECTED_VERIFIER_ERROR"),
                StatusCode::UNEXPECTED_DESERIALIZATION_ERROR => unreachable!("UNEXPECTED_DESERIALIZATION_ERROR"),
                _ => (),
            }
        }
    }
}
