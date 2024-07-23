// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{ffi, Error, ErrorInternal, Result};
use std::fmt;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl From<AddrFamily> for u8 {
    fn from(af: AddrFamily) -> Self {
        match af {
            AddrFamily::Any => ffi::pfvar::PF_UNSPEC as u8,
            AddrFamily::Ipv4 => ffi::pfvar::PF_INET as u8,
            AddrFamily::Ipv6 => ffi::pfvar::PF_INET6 as u8,
        }
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
        const UNSPEC: u8 = ffi::pfvar::PF_UNSPEC as u8;
        const INET: u8 = ffi::pfvar::PF_INET as u8;
        const INET6: u8 = ffi::pfvar::PF_INET6 as u8;

        match family {
            UNSPEC => Ok(AddrFamily::Any),
            INET => Ok(AddrFamily::Ipv4),
            INET6 => Ok(AddrFamily::Ipv6),
            _ => Err(Error::from(ErrorInternal::InvalidAddressFamily(family))),
        }
    }
}
