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
    ($func:expr) => {
        ioctl_guard!($func, libc::EEXIST)
    };
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
    };
}
