// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub const IOCTL_ERROR: i32 = -1;

/// Macro for taking an expression with an ioctl call, perform it and return a Rust ´Result´.
macro_rules! ioctl_guard {
    ($func:expr) => {
        ioctl_guard!($func, libc::EEXIST)
    };
    ($func:expr, $already_active:expr) => {
        if unsafe { $func } == $crate::macros::IOCTL_ERROR {
            let io_error = ::std::io::Error::last_os_error();
            let error_code = io_error
                .raw_os_error()
                .expect("Errors created with last_os_error should have errno");

            Err($crate::Error::from(if error_code == $already_active {
                $crate::ErrorInternal::StateAlreadyActive
            } else {
                $crate::ErrorInternal::Ioctl(io_error)
            }))
        } else {
            Ok(()) as $crate::Result<()>
        }
    };
}
