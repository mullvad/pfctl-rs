// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{Error, ErrorKind, Result};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    #[default]
    Any,
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
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

    fn try_from(direction: u8) -> Result<Self> {
        match direction as i32 {
            libc::IPPROTO_IP => Ok(Proto::Any),
            libc::IPPROTO_TCP => Ok(Proto::Tcp),
            libc::IPPROTO_UDP => Ok(Proto::Udp),
            libc::IPPROTO_ICMP => Ok(Proto::Icmp),
            libc::IPPROTO_ICMPV6 => Ok(Proto::IcmpV6),
            _ => Err(Error::from_kind(ErrorKind::InvalidArgument(
                "Invalid protocol",
            ))),
        }
    }
}
