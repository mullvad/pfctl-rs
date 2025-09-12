// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Error, ErrorInternal, Result};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Proto {
    #[default]
    Any = libc::IPPROTO_IP as u8,
    Tcp = libc::IPPROTO_TCP as u8,
    Udp = libc::IPPROTO_UDP as u8,
    Icmp = libc::IPPROTO_ICMP as u8,
    IcmpV6 = libc::IPPROTO_ICMPV6 as u8,
}

impl From<Proto> for u8 {
    fn from(proto: Proto) -> Self {
        match proto {
            Proto::Any => libc::IPPROTO_IP as u8,
            Proto::Tcp => libc::IPPROTO_TCP as u8,
            Proto::Udp => libc::IPPROTO_UDP as u8,
            Proto::Icmp => libc::IPPROTO_ICMP as u8,
            Proto::IcmpV6 => libc::IPPROTO_ICMPV6 as u8,
        }
    }
}

impl TryFrom<u8> for Proto {
    type Error = crate::Error;

    fn try_from(proto: u8) -> Result<Self> {
        match proto {
            v if v == Proto::Any as u8 => Ok(Proto::Any),
            v if v == Proto::Tcp as u8 => Ok(Proto::Tcp),
            v if v == Proto::Udp as u8 => Ok(Proto::Udp),
            v if v == Proto::Icmp as u8 => Ok(Proto::Icmp),
            v if v == Proto::IcmpV6 as u8 => Ok(Proto::IcmpV6),
            _ => Err(Error::from(ErrorInternal::InvalidTransportProtocol(proto))),
        }
    }
}
