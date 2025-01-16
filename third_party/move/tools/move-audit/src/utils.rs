use log::LevelFilter;

/// Execute a closure with logging completely disabled
pub fn with_logging_disabled<R, F: FnOnce() -> R>(f: F) -> R {
    let level = log::max_level();
    log::set_max_level(LevelFilter::Off);
    let ret = f();
    log::set_max_level(level);
    ret
}
