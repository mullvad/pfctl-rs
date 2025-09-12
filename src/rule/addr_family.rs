// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Error, ErrorInternal, Result, ffi};
use std::fmt;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum AddrFamily {
    #[default]
    Any = ffi::pfvar::PF_UNSPEC as u8,
    Ipv4 = ffi::pfvar::PF_INET as u8,
    Ipv6 = ffi::pfvar::PF_INET6 as u8,
}

impl From<AddrFamily> for u8 {
    fn from(af: AddrFamily) -> Self {
        af as u8
    }
}

impl fmt::Display for AddrFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> ::std::result::Result<(), fmt::Error> {
        match *self {
            AddrFamily::Any => "any",
            AddrFamily::Ipv4 => "IPv4",
            AddrFamily::Ipv6 => "IPv6",
        }
        .fmt(f)
    }
}

impl TryFrom<u8> for AddrFamily {
    type Error = crate::Error;

    fn try_from(family: u8) -> Result<Self> {
        match family {
            v if v == AddrFamily::Any as u8 => Ok(AddrFamily::Any),
            v if v == AddrFamily::Ipv4 as u8 => Ok(AddrFamily::Ipv4),
            v if v == AddrFamily::Ipv6 as u8 => Ok(AddrFamily::Ipv6),
            _ => Err(Error::from(ErrorInternal::InvalidAddressFamily(family))),
        }
    }
}
