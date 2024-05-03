// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{AddrFamily, Ip, Port};
use crate::{
    conversion::{CopyTo, TryCopyTo},
    ffi, Result,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Endpoint {
    ip: Ip,
    port: Port,
}

impl Endpoint {
    pub fn new<IP: Into<Ip>, PORT: Into<Port>>(ip: IP, port: PORT) -> Self {
        Endpoint {
            ip: ip.into(),
            port: port.into(),
        }
    }

    pub fn ip(&self) -> Ip {
        self.ip
    }

    pub fn port(&self) -> Port {
        self.port
    }

    pub fn get_af(&self) -> AddrFamily {
        self.ip.get_af()
    }
}

impl From<Ip> for Endpoint {
    fn from(ip: Ip) -> Self {
        Endpoint::new(ip, Port::default())
    }
}

impl From<Port> for Endpoint {
    fn from(port: Port) -> Self {
        Endpoint::new(Ip::default(), port)
    }
}

impl From<Ipv4Addr> for Endpoint {
    fn from(ip: Ipv4Addr) -> Self {
        Self::from(Ip::from(ip))
    }
}

impl From<Ipv6Addr> for Endpoint {
    fn from(ip: Ipv6Addr) -> Self {
        Self::from(Ip::from(ip))
    }
}

impl From<IpAddr> for Endpoint {
    fn from(ip: IpAddr) -> Self {
        Self::from(Ip::from(ip))
    }
}

impl From<SocketAddrV4> for Endpoint {
    fn from(socket_addr: SocketAddrV4) -> Self {
        Endpoint::new(Ip::from(*socket_addr.ip()), Port::from(socket_addr.port()))
    }
}

impl From<SocketAddrV6> for Endpoint {
    fn from(socket_addr: SocketAddrV6) -> Self {
        Endpoint::new(Ip::from(*socket_addr.ip()), Port::from(socket_addr.port()))
    }
}

impl From<SocketAddr> for Endpoint {
    fn from(socket_addr: SocketAddr) -> Self {
        match socket_addr {
            SocketAddr::V4(addr) => Endpoint::from(addr),
            SocketAddr::V6(addr) => Endpoint::from(addr),
        }
    }
}

impl TryCopyTo<ffi::pfvar::pf_rule_addr> for Endpoint {
    type Result = Result<()>;

    fn try_copy_to(&self, pf_rule_addr: &mut ffi::pfvar::pf_rule_addr) -> Self::Result {
        self.ip.copy_to(&mut pf_rule_addr.addr);
        self.port
            .try_copy_to(unsafe { &mut pf_rule_addr.xport.range })?;
        Ok(())
    }
}
