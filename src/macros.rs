// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Macro for taking an expression with an ioctl call, perform it and return a Rust ´Result´.
macro_rules! ioctl_guard {
    ($func:expr) => {
        ioctl_guard!($func, libc::EEXIST)
    };
    ($func:expr, $already_active:expr) => {
        // nix::ioctl calls return error numbers out of box.
        if let nix::Result::Err(errno) = unsafe { $func } {
            let error_code = errno as i32;
            let mut err = Err($crate::ErrorKind::IoctlError(std::io::Error::from_raw_os_error(error_code)).into());
            if error_code == $already_active {
                err = err.chain_err(|| $crate::ErrorKind::StateAlreadyActive);
            }
            err
        } else {
            Ok(()) as $crate::Result<()>
        }
    };
}
