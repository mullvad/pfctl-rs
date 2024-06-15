#[cfg(target_os = "macos")]
include!("./pfvar/macos.rs");

#[cfg(target_os = "freebsd")]
include!("./pfvar/freebsd.rs");

#[cfg(target_os = "openbsd")]
include!("./pfvar/openbsd.rs");

// FreeBSD uses different (but mostly compatible) pfsync_state between FreeBSD 13 and 14
#[cfg(target_os = "freebsd")]
pub use pfsync_state_1301 as pfsync_state;
