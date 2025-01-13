// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{
    conversion::CopyTo,
    ffi,
    pooladdr::{PoolAddr, PoolAddrList},
    AddrFamily, Result,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ip {
    #[default]
    Any,
    Net(IpNetwork),
}

impl Ip {
    pub fn get_af(&self) -> AddrFamily {
        match *self {
            Ip::Any => AddrFamily::Any,
            Ip::Net(network) => network.get_af(),
        }
    }

    /// Returns `Ip::Any` represented an as an `IpNetwork`, used for ffi.
    fn any_ffi_repr() -> IpNetwork {
        IpNetwork::new(Ipv6Addr::UNSPECIFIED, 0)
    }

    /// Returns PoolAddrList initialized with receiver
    pub fn to_pool_addr_list(&self) -> Result<PoolAddrList> {
        PoolAddrList::new(&[PoolAddr::from(*self)])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpNetwork(ipnetwork::IpNetwork);

impl IpNetwork {
    pub fn new(ip: impl Into<IpAddr>, prefix: u8) -> IpNetwork {
        Self::new_checked(ip.into(), prefix).unwrap()
    }

    pub const fn new_checked(ip: IpAddr, prefix: u8) -> Option<IpNetwork> {
        match ip {
            IpAddr::V4(ipv4_addr) => Self::v4(ipv4_addr, prefix),
            IpAddr::V6(ipv6_addr) => Self::v6(ipv6_addr, prefix),
        }
    }

    /// Create an IPv4 network.
    pub const fn v4(ip: Ipv4Addr, prefix: u8) -> Option<IpNetwork> {
        let Some(network) = ipnetwork::Ipv4Network::new_checked(ip, prefix) else {
            return None;
        };
        Some(IpNetwork(ipnetwork::IpNetwork::V4(network)))
    }

    /// Create an IPv6 network.
    pub const fn v6(ip: Ipv6Addr, prefix: u8) -> Option<IpNetwork> {
        let Some(network) = ipnetwork::Ipv6Network::new_checked(ip, prefix) else {
            return None;
        };
        Some(IpNetwork(ipnetwork::IpNetwork::V6(network)))
    }

    pub fn ip(&self) -> IpAddr {
        self.0.ip()
    }

    pub fn mask(&self) -> IpAddr {
        self.0.mask()
    }

    const fn get_af(&self) -> AddrFamily {
        match self.0 {
            ipnetwork::IpNetwork::V4(_) => AddrFamily::Ipv4,
            ipnetwork::IpNetwork::V6(_) => AddrFamily::Ipv6,
        }
    }
}

impl From<IpNetwork> for Ip {
    fn from(net: IpNetwork) -> Self {
        Ip::Net(net)
    }
}

impl From<Ipv4Addr> for Ip {
    fn from(ip: Ipv4Addr) -> Self {
        Ip::from(IpNetwork::new(ip, 32))
    }
}

impl From<Ipv6Addr> for Ip {
    fn from(ip: Ipv6Addr) -> Self {
        Ip::from(IpNetwork::new(ip, 128))
    }
}

impl From<IpAddr> for Ip {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(addr) => Ip::from(addr),
            IpAddr::V6(addr) => Ip::from(addr),
        }
    }
}

impl CopyTo<ffi::pfvar::pf_addr_wrap> for Ip {
    fn copy_to(&self, pf_addr_wrap: &mut ffi::pfvar::pf_addr_wrap) {
        match *self {
            Ip::Any => Self::any_ffi_repr().copy_to(pf_addr_wrap),
            Ip::Net(net) => net.copy_to(pf_addr_wrap),
        }
    }
}
