// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{conversion::TryCopyTo, ffi, AnchorKind, ErrorKind, PoolAddr, Result, ResultExt};
use std::{
    fs::{File, OpenOptions},
    mem,
    os::unix::io::RawFd,
};

/// The path to the PF device file this library will use to communicate with PF.
const PF_DEV_PATH: &str = "/dev/pf";

/// Open PF virtual device
pub fn open_pf() -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(PF_DEV_PATH)
        .chain_err(|| ErrorKind::DeviceOpenError(PF_DEV_PATH))
}

/// Add pool address using the pool ticket previously obtained via `get_pool_ticket()`
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub fn add_pool_address<A: Into<PoolAddr>>(
    fd: RawFd,
    pool_addr: A,
    pool_ticket: u32,
) -> Result<()> {
    let mut pfioc_pooladdr = unsafe { mem::zeroed::<ffi::pfvar::pfioc_pooladdr>() };
    pfioc_pooladdr.ticket = pool_ticket;
    pool_addr.into().try_copy_to(&mut pfioc_pooladdr.addr)?;
    ioctl_guard!(ffi::pf_add_addr(fd, &mut pfioc_pooladdr))
}

/// Get pool ticket
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub fn get_pool_ticket(fd: RawFd) -> Result<u32> {
    let mut pfioc_pooladdr = unsafe { mem::zeroed::<ffi::pfvar::pfioc_pooladdr>() };
    ioctl_guard!(ffi::pf_begin_addrs(fd, &mut pfioc_pooladdr))?;
    Ok(pfioc_pooladdr.ticket)
}

pub fn get_ticket(
    fd: RawFd,
    anchor:&str,
    #[cfg(target_os = "macos")]
    kind: AnchorKind
) -> Result<u32> {
    let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
    #[cfg(target_os = "macos")] {
        pfioc_rule.action = ffi::pfvar::PF_CHANGE_GET_TICKET as u32;
        pfioc_rule.rule.action = kind.into();
    }
    // pfioc_rule.action is ignored on FreeBSD and OpenBSD
    #[cfg(any(target_os = "openbsd", target_os = "freebsd"))] {
        pfioc_rule.rule.action = ffi::pfvar::PF_CHANGE_GET_TICKET as u8;
    }
    anchor
        .try_copy_to(&mut pfioc_rule.anchor[..])
        .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
    ioctl_guard!(ffi::pf_change_rule(fd, &mut pfioc_rule))?;
    Ok(pfioc_rule.ticket)
}
