use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::ffi::pfvar::pfsync_state_host;
use crate::{ffi::pfvar::pfsync_state, Direction, Proto};
use crate::{AddrFamily, Error, ErrorInternal, Result};

/// PF connection state created by a stateful rule
#[derive(Debug, Clone)]
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
        Proto::try_from(self.sync_state.proto)
    }

    /// Return the local socket address for this state
    pub fn local_address(&self) -> Result<SocketAddr> {
        parse_address(self.sync_state.af_lan, self.sync_state.lan)
    }

    /// Return the remote socket address for this state
    pub fn remote_address(&self) -> Result<SocketAddr> {
        parse_address(self.sync_state.af_lan, self.sync_state.ext_lan)
    }

    /// Return a reference to the inner `pfsync_state` state
    pub(crate) fn as_raw(&self) -> &pfsync_state {
        &self.sync_state
    }
}

fn parse_address(family: u8, host: pfsync_state_host) -> Result<SocketAddr> {
    let ip = match AddrFamily::try_from(family) {
        Ok(AddrFamily::Ipv4) => Ipv4Addr::from(u32::from_be(
            unsafe { host.addr.pfa._v4addr.as_ref() }.s_addr,
        ))
        .into(),
        Ok(AddrFamily::Ipv6) => {
            Ipv6Addr::from(*unsafe { host.addr.pfa._v6addr.as_ref().__u6_addr.__u6_addr8.as_ref() })
                .into()
        }
        _ => return Err(Error::from(ErrorInternal::InvalidAddressFamily(family))),
    };
    let port = u16::from_be(unsafe { *host.xport.port.as_ref() });

    Ok(SocketAddr::new(ip, port))
}
