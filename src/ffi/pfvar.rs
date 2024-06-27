#[cfg(target_os = "macos")]
include!("./pfvar/macos.rs");

#[cfg(target_os = "freebsd")]
include!("./pfvar/freebsd.rs");

#[cfg(target_os = "openbsd")]
include!("./pfvar/openbsd.rs");

#[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd")))]
compile_error!("Current operating system is not supported!");

// FreeBSD uses different (but mostly compatible) pfsync_state between FreeBSD 13 and 14
#[cfg(target_os = "freebsd")]
pub use pfsync_state_1301 as pfsync_state;
