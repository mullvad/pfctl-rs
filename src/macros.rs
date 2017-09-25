// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub const IOCTL_ERROR: i32 = -1;

/// Macro for taking an expression with an ioctl call, perform it and return a Rust ´Result´.
macro_rules! ioctl_guard {
    ($func:expr) => (ioctl_guard!($func, $crate::libc::EEXIST));
    ($func:expr, $already_active:expr) => {
        if unsafe { $func } == $crate::macros::IOCTL_ERROR {
            let ::errno::Errno(error_code) = ::errno::errno();
            let io_error = ::std::io::Error::from_raw_os_error(error_code);
            let mut err = Err($crate::ErrorKind::IoctlError(io_error).into());
            if error_code == $already_active {
                err = err.chain_err(|| $crate::ErrorKind::StateAlreadyActive);
            }
            err
        } else {
            Ok(()) as $crate::Result<()>
        }
    }
}

/// Delay between retries (in milliseconds)
pub const RETRY_IF_BUSY_DELAY: u64 = 100;

/// Maximum number of retries to perform before giving up
pub const RETRY_IF_BUSY_MAX: i8 = 5;

/// Helper macro that runs the given expression if received error indicates that firewall rules
/// were modified concurrently by other program until either timeout, or number of retries reached,
/// or any other result occurred.
macro_rules! retry_on_busy {
    ($body:expr) => ({
        let delay = ::std::time::Duration::from_millis($crate::macros::RETRY_IF_BUSY_DELAY);
        let mut retry = 0;
        let mut result;
        loop {
            result = $body;
            match result {
                Err($crate::Error($crate::ErrorKind::IoctlError(ref io_err), _))
                    if io_err.raw_os_error() == Some($crate::libc::EBUSY) &&
                       retry < $crate::macros::RETRY_IF_BUSY_MAX => {
                    retry += 1;
                    ::std::thread::sleep(delay);
                }
                _ => break
            };
        };
        result
    })
}
