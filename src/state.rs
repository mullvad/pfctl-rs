use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::ffi::pfvar::pfsync_state_host;
use crate::{ffi::pfvar::pfsync_state, Direction, Proto};
use crate::{AddrFamily, Error, ErrorInternal, Result};

/// PF connection state created by a stateful rule
#[derive(Clone)]
pub struct State {
    sync_state: pfsync_state,
}

impl State {
    pub(crate) fn new(sync_state: pfsync_state) -> State {
        State { sync_state }
    }

    /// Return the direction for this state
    pub fn direction(&self) -> Result<Direction> {
        Direction::try_from(self.sync_state.direction)
    }

    /// Return the transport protocol for this state
    pub fn proto(&self) -> Result<Proto> {
        Proto::try_from(self.sync_state.direction)
    }

    /// Return the local socket address for this state
    pub fn local_address(&self) -> Result<SocketAddr> {
        parse_address(self.sync_state.af_lan, self.sync_state.lan)
    }

    /// Return the remote socket address for this state
    pub fn remote_address(&self) -> Result<SocketAddr> {
        parse_address(self.sync_state.af_lan, self.sync_state.ext_lan)
    }
}

fn parse_address(family: u8, host: pfsync_state_host) -> Result<SocketAddr> {
    let ip = match AddrFamily::try_from(family) {
        Ok(AddrFamily::Ipv4) => {
            Ipv4Addr::from(unsafe { host.addr.pfa._v4addr.s_addr }.to_be()).into()
        }
        Ok(AddrFamily::Ipv6) => {
            Ipv6Addr::from(unsafe { host.addr.pfa._v6addr.__u6_addr.__u6_addr8 }).into()
        }
        _ => return Err(Error::from(ErrorInternal::InvalidAddressFamily(family))),
    };
    let port = unsafe { host.xport.port }.to_be();

    Ok(SocketAddr::new(ip, port))
}
