use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::ffi::pfvar::pfsync_state_host;
use crate::{ffi::pfvar::pfsync_state, Direction, Proto};
use crate::{AddrFamily, Error, ErrorKind, Result};

/// PF connection state
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub enum State {
    /// IP connection state
    Ip(IpState),
    /// Any connection state that could not be parsed
    Raw(pfsync_state),
}

/// IP connection
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IpState {
    pub direction: Direction,
    pub proto: Proto,
    pub local_address: SocketAddr,
    pub remote_address: SocketAddr,
}

impl From<pfsync_state> for State {
    fn from(state: pfsync_state) -> Self {
        IpState::try_from(state)
            .map(State::Ip)
            .unwrap_or_else(|_| State::Raw(state))
    }
}

impl TryFrom<pfsync_state> for IpState {
    type Error = Error;

    fn try_from(state: pfsync_state) -> Result<Self> {
        Ok(IpState {
            direction: Direction::try_from(state.direction)?,
            proto: Proto::try_from(state.proto)?,
            local_address: parse_address(state.af_lan, state.lan)?,
            remote_address: parse_address(state.af_lan, state.ext_lan)?,
        })
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
        _ => {
            return Err(Error::from_kind(ErrorKind::InvalidArgument(
                "Not an IP address",
            )))
        }
    };
    let port = unsafe { host.xport.port }.to_be();

    Ok(SocketAddr::new(ip, port))
}
