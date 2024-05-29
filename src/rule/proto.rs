// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

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
