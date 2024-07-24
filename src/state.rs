use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::ffi::pfvar::pfsync_state_host;
use crate::{ffi::pfvar::pfsync_state, Direction, Proto};
use crate::{Error, ErrorInternal, Result};

/// PF connection state created by a stateful rule
#[derive(Clone)]
pub struct State {
    sync_state: pfsync_state,
}

// Manually derive `Debug` since `pfsync_state` contains unions.
impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("State")
            .field("direction", &self.direction())
            .field("proto", &self.proto())
            .field("local_address", &self.local_address())
            .field("remote_address", &self.remote_address())
            .finish()
    }
}

impl State {
    /// Wrap `pfsync_state` so that it can be accessed safely.
    ///
    /// # Safety
    ///
    /// `sync_state.lan` and `sync_state.ext_lan` must set an address and port:
    /// * If `sync_state.af_lan == PF_INET`, then `host.addr.pfa._v4addr` must be initialized.
    /// * If `sync_state.af_lan == PF_INET6`, then `host.addr.pfa._v6addr` must be initialized.
    /// * `host.xport.port` must be initialized.
    pub(crate) unsafe fn new(sync_state: pfsync_state) -> State {
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
        // SAFETY: The address and port are initialized according to the contract of `Self::new`.
        unsafe { parse_address(self.sync_state.af_lan, self.sync_state.lan) }
    }

    /// Return the remote socket address for this state
    pub fn remote_address(&self) -> Result<SocketAddr> {
        // SAFETY: The address and port are initialized according to the contract of `Self::new`.
        unsafe { parse_address(self.sync_state.af_lan, self.sync_state.ext_lan) }
    }

    /// Return a reference to the inner `pfsync_state` state
    pub(crate) fn as_raw(&self) -> &pfsync_state {
        &self.sync_state
    }
}

/// Parse an IP address and port from a `pfsync_sync_host`, normally provided by `pfsync_state`.
///
/// # Safety
///
/// `host` must contain a valid address and a port:
/// * If `family == PF_INET`, then `host.addr.pfa._v4addr` must be initialized.
/// * If `family == PF_INET6`, then `host.addr.pfa._v6addr` must be initialized.
/// * `host.xport.port` must always be initialized.
unsafe fn parse_address(family: u8, host: pfsync_state_host) -> Result<SocketAddr> {
    let ip = match u32::from(family) {
        crate::ffi::pfvar::PF_INET => {
            // SAFETY: The caller has initialized this memory
            Ipv4Addr::from(u32::from_be(unsafe { host.addr.pfa._v4addr.s_addr })).into()
        }
        crate::ffi::pfvar::PF_INET6 => {
            // SAFETY: The caller has initialized this memory
            Ipv6Addr::from(unsafe { host.addr.pfa._v6addr.__u6_addr.__u6_addr8 }).into()
        }
        _ => return Err(Error::from(ErrorInternal::InvalidAddressFamily(family))),
    };

    // SAFETY: The caller has initialized this memory
    let port = u16::from_be(unsafe { host.xport.port });

    Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::pfsync_state_host;
    use crate::{state::parse_address, AddrFamily};

    use assert_matches::assert_matches;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_parse_ipv4_address() {
        const EXPECTED_IP: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
        const EXPECTED_PORT: u16 = 12345;

        let mut host: pfsync_state_host = unsafe { std::mem::zeroed() };
        host.addr.pfa._v4addr.s_addr = u32::from_be_bytes(EXPECTED_IP.octets()).to_be();
        host.xport.port = EXPECTED_PORT.to_be();

        let family = u8::from(AddrFamily::Ipv4);

        assert_matches!(unsafe { parse_address(family, host) }, Ok(addr) if addr == SocketAddr::new(EXPECTED_IP.into(), EXPECTED_PORT));
    }

    #[test]
    fn test_parse_ipv6_address() {
        const EXPECTED_IP: Ipv6Addr = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 0x7f);
        const EXPECTED_PORT: u16 = 12345;

        let mut host: pfsync_state_host = unsafe { std::mem::zeroed() };
        host.addr.pfa._v6addr.__u6_addr.__u6_addr8 = EXPECTED_IP.octets();
        host.xport.port = EXPECTED_PORT.to_be();

        let family = u8::from(AddrFamily::Ipv6);

        assert_matches!(unsafe { parse_address(family, host) }, Ok(addr) if addr == SocketAddr::new(EXPECTED_IP.into(), EXPECTED_PORT));
    }
}
