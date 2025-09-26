// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use zerocopy::FromZeros;

use crate::{AnchorKind, Error, ErrorInternal, PoolAddr, Result, conversion::TryCopyTo, ffi};
use std::{
    fs::{File, OpenOptions},
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
        .map_err(|e| Error::from(ErrorInternal::DeviceOpen(PF_DEV_PATH, e)))
}

/// Add pool address using the pool ticket previously obtained via `get_pool_ticket()`
pub fn add_pool_address<A: Into<PoolAddr>>(
    fd: RawFd,
    pool_addr: A,
    pool_ticket: u32,
) -> Result<()> {
    let mut pfioc_pooladdr = ffi::pfvar::pfioc_pooladdr::new_zeroed();
    pfioc_pooladdr.ticket = pool_ticket;
    pool_addr.into().try_copy_to(&mut pfioc_pooladdr.addr)?;
    ioctl_guard!(ffi::pf_add_addr(fd, &mut pfioc_pooladdr))
}

/// Get pool ticket
pub fn get_pool_ticket(fd: RawFd) -> Result<u32> {
    let mut pfioc_pooladdr = ffi::pfvar::pfioc_pooladdr::new_zeroed();
    ioctl_guard!(ffi::pf_begin_addrs(fd, &mut pfioc_pooladdr))?;
    Ok(pfioc_pooladdr.ticket)
}

pub fn get_ticket(fd: RawFd, anchor: &str, kind: AnchorKind) -> Result<u32> {
    let mut pfioc_rule = ffi::pfvar::pfioc_rule::new_zeroed();
    pfioc_rule.action = ffi::pfvar::PF_CHANGE_GET_TICKET as u32;
    pfioc_rule.rule.action = kind.into();
    copy_anchor_name(anchor, &mut pfioc_rule.anchor[..])?;
    ioctl_guard!(ffi::pf_change_rule(fd, &mut pfioc_rule))?;
    Ok(pfioc_rule.ticket)
}

pub fn copy_anchor_name(anchor: &str, destination: &mut [i8]) -> Result<()> {
    anchor
        .try_copy_to(destination)
        .map_err(|reason| Error::from(ErrorInternal::InvalidAnchorName(reason)))
}
