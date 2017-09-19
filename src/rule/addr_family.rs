// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use ffi;

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrFamily {
    Any,
    Ipv4,
    Ipv6,
}

impl Default for AddrFamily {
    fn default() -> Self {
        AddrFamily::Any
    }
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
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        match *self {
            AddrFamily::Any => "any",
            AddrFamily::Ipv4 => "IPv4",
            AddrFamily::Ipv6 => "IPv6",
        }.fmt(f)
    }
}
