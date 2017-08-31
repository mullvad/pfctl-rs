// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use {AnchorKind, ErrorKind, Result, ResultExt};
use conversion::TryCopyTo;
use ffi;

use std::fs::{File, OpenOptions};
use std::mem;
use std::os::unix::io::RawFd;

/// The path to the PF device file this library will use to communicate with PF.
const PF_DEV_PATH: &'static str = "/dev/pf";

/// Open PF virtual device
pub fn open_pf() -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(PF_DEV_PATH)
        .chain_err(|| ErrorKind::DeviceOpenError(PF_DEV_PATH))
}

/// Get pool ticket
pub fn get_pool_ticket(fd: RawFd, anchor: &str) -> Result<u32> {
    let mut pfioc_pooladdr = unsafe { mem::zeroed::<ffi::pfvar::pfioc_pooladdr>() };
    pfioc_pooladdr.action = ffi::pfvar::PF_CHANGE_GET_TICKET as u32;
    anchor
        .try_copy_to(&mut pfioc_pooladdr.anchor[..])
        .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
    ioctl_guard!(ffi::pf_begin_addrs(fd, &mut pfioc_pooladdr))?;
    Ok(pfioc_pooladdr.ticket)
}

pub fn get_ticket(fd: RawFd, anchor: &str, kind: AnchorKind) -> Result<u32> {
    let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
    pfioc_rule.action = ffi::pfvar::PF_CHANGE_GET_TICKET as u32;
    pfioc_rule.rule.action = kind.into();
    anchor
        .try_copy_to(&mut pfioc_rule.anchor[..])
        .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
    ioctl_guard!(ffi::pf_change_rule(fd, &mut pfioc_rule))?;
    Ok(pfioc_rule.ticket)
}
