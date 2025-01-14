use crate::common::PkgDefinition;
use log::info;

/// Hold all information about the fuzz targets
pub struct FuzzModel {}

impl FuzzModel {
    /// Create the fuzz model from compiled packages
    pub fn new(pkgs: &[PkgDefinition]) -> Self {
        for pkg in pkgs {
            info!(
                "Package: {}",
                pkg.as_compiled_package().compiled_package_info.package_name
            );
        }
        Self {}
    }
}
