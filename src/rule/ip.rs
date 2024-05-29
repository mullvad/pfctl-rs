// Copyright 2017 Amagicom AB.
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
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
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
            Ip::Net(IpNetwork::V4(_)) => AddrFamily::Ipv4,
            Ip::Net(IpNetwork::V6(_)) => AddrFamily::Ipv6,
        }
    }

    /// Returns `Ip::Any` represented an as an `IpNetwork`, used for ffi.
    fn any_ffi_repr() -> IpNetwork {
        IpNetwork::V6(Ipv6Network::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0).unwrap())
    }

    /// Returns PoolAddrList initialized with receiver
    pub fn to_pool_addr_list(&self) -> Result<PoolAddrList> {
        PoolAddrList::new(&[PoolAddr::from(*self)])
    }
}

impl From<IpNetwork> for Ip {
    fn from(net: IpNetwork) -> Self {
        Ip::Net(net)
    }
}

impl From<Ipv4Addr> for Ip {
    fn from(ip: Ipv4Addr) -> Self {
        Ip::Net(IpNetwork::V4(Ipv4Network::new(ip, 32).unwrap()))
    }
}

impl From<Ipv6Addr> for Ip {
    fn from(ip: Ipv6Addr) -> Self {
        Ip::Net(IpNetwork::V6(Ipv6Network::new(ip, 128).unwrap()))
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
