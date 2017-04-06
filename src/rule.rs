use conversion::{ToFfi, CopyToFfi};
use ffi;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

use libc;

use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[derive(Builder)]
pub struct FilterRule {
    action: RuleAction,
    #[builder(default)]
    direction: Direction,
    #[builder(default)]
    quick: bool,
    #[builder(default)]
    proto: Proto,
    #[builder(default)]
    af: AddrFamily,
    #[builder(default)]
    from: Endpoint,
    #[builder(default)]
    to: Endpoint,
}

impl CopyToFfi<ffi::pfvar::pf_rule> for FilterRule {
    fn copy_to(&self, pf_rule: &mut ffi::pfvar::pf_rule) -> ::Result<()> {
        pf_rule.action = self.action.to_ffi();
        pf_rule.direction = self.direction.to_ffi();
        pf_rule.quick = self.quick.to_ffi();
        pf_rule.af = self.af.to_ffi();
        pf_rule.proto = self.proto.to_ffi();
        self.from.copy_to(&mut pf_rule.src)?;
        self.to.copy_to(&mut pf_rule.dst)?;
        Ok(())
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Endpoint(Ip, Port);

impl From<Ip> for Endpoint {
    fn from(ip: Ip) -> Self {
        Endpoint(ip, Port::default())
    }
}

impl From<Port> for Endpoint {
    fn from(port: Port) -> Self {
        Endpoint(Ip::default(), port)
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

impl CopyToFfi<ffi::pfvar::pf_rule_addr> for Endpoint {
    fn copy_to(&self, pf_rule_addr: &mut ffi::pfvar::pf_rule_addr) -> ::Result<()> {
        let Endpoint(ref ip, ref port) = *self;
        ip.copy_to(&mut pf_rule_addr.addr)?;
        port.copy_to(unsafe { pf_rule_addr.xport.range.as_mut() })?;
        Ok(())
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ip(IpNetwork);

impl Ip {
    pub fn any() -> Self {
        Ip(IpNetwork::V6(Ipv6Network::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0).unwrap()))
    }
}

impl Default for Ip {
    fn default() -> Self {
        Ip::any()
    }
}

impl From<IpNetwork> for Ip {
    fn from(net: IpNetwork) -> Self {
        Ip(net)
    }
}

impl From<Ipv4Addr> for Ip {
    fn from(ip: Ipv4Addr) -> Self {
        Ip(IpNetwork::V4(Ipv4Network::new(ip, 32).unwrap()))
    }
}

impl From<Ipv6Addr> for Ip {
    fn from(ip: Ipv6Addr) -> Self {
        Ip(IpNetwork::V6(Ipv6Network::new(ip, 128).unwrap()))
    }
}

impl CopyToFfi<ffi::pfvar::pf_addr_wrap> for Ip {
    fn copy_to(&self, pf_addr_wrap: &mut ffi::pfvar::pf_addr_wrap) -> ::Result<()> {
        self.0.copy_to(pf_addr_wrap)
    }
}


/// Enum describing what should happen to a packet that matches a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleAction {
    Pass,
    Drop,
}

impl ToFfi<u8> for RuleAction {
    fn to_ffi(&self) -> u8 {
        match *self {
            RuleAction::Pass => ffi::pfvar::PF_PASS as u8,
            RuleAction::Drop => ffi::pfvar::PF_DROP as u8,
        }
    }
}


/// Enum describing matching of rule towards packet flow direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    Any,
    In,
    Out,
}

impl Default for Direction {
    fn default() -> Self {
        Direction::Any
    }
}

impl ToFfi<u8> for Direction {
    fn to_ffi(&self) -> u8 {
        match *self {
            Direction::Any => ffi::pfvar::PF_INOUT as u8,
            Direction::In => ffi::pfvar::PF_IN as u8,
            Direction::Out => ffi::pfvar::PF_OUT as u8,
        }
    }
}


// TODO(linus): Many more protocols to add. But this will do for now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Any,
    Tcp,
}

impl Default for Proto {
    fn default() -> Self {
        Proto::Any
    }
}

impl ToFfi<u8> for Proto {
    fn to_ffi(&self) -> u8 {
        match *self {
            Proto::Any => libc::IPPROTO_IP as u8,
            Proto::Tcp => libc::IPPROTO_TCP as u8,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AddrFamily {
    Any,
    Ipv4,
    Ipv6,
}

impl Default for AddrFamily {
    fn default() -> Self {
        AddrFamily::Any
    }
}

impl ToFfi<u8> for AddrFamily {
    fn to_ffi(&self) -> u8 {
        match *self {
            AddrFamily::Any => ffi::pfvar::PF_UNSPEC as u8,
            AddrFamily::Ipv4 => ffi::pfvar::PF_INET as u8,
            AddrFamily::Ipv6 => ffi::pfvar::PF_INET6 as u8,
        }
    }
}

// Port range representation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Port {
    Any,
    One(u16, PortUnaryModifier),
    Range(u16, u16, PortRangeModifier),
}

impl Default for Port {
    fn default() -> Self {
        Port::Any
    }
}

impl From<u16> for Port {
    fn from(port: u16) -> Self {
        Port::One(port, PortUnaryModifier::Equal)
    }
}

impl CopyToFfi<ffi::pfvar::pf_port_range> for Port {
    fn copy_to(&self, pf_port_range: &mut ffi::pfvar::pf_port_range) -> ::Result<()> {
        match *self {
            Port::Any => {
                pf_port_range.op = ffi::pfvar::PF_OP_NONE as u8;
                pf_port_range.port[0] = 0;
                pf_port_range.port[1] = 0;
            }
            Port::One(port, modifier) => {
                pf_port_range.op = modifier.to_ffi();
                // convert port range to network byte order
                pf_port_range.port[0] = port.to_be();
                pf_port_range.port[1] = 0;
            }
            Port::Range(start_port, end_port, modifier) => {
                ensure!(start_port <= end_port,
                        ::ErrorKind::InvalidArgument("Lower port is greater than upper port."));
                pf_port_range.op = modifier.to_ffi();
                // convert port range to network byte order
                pf_port_range.port[0] = start_port.to_be();
                pf_port_range.port[1] = end_port.to_be();
            }
        }
        Ok(())
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortUnaryModifier {
    Equal,
    NotEqual,
    Greater,
    Less,
    GreaterOrEqual,
    LessOrEqual,
}

impl ToFfi<u8> for PortUnaryModifier {
    fn to_ffi(&self) -> u8 {
        match *self {
            PortUnaryModifier::Equal => ffi::pfvar::PF_OP_EQ as u8,
            PortUnaryModifier::NotEqual => ffi::pfvar::PF_OP_NE as u8,
            PortUnaryModifier::Greater => ffi::pfvar::PF_OP_GT as u8,
            PortUnaryModifier::Less => ffi::pfvar::PF_OP_LT as u8,
            PortUnaryModifier::GreaterOrEqual => ffi::pfvar::PF_OP_GE as u8,
            PortUnaryModifier::LessOrEqual => ffi::pfvar::PF_OP_LE as u8,
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortRangeModifier {
    Exclusive,
    Inclusive,
    Except,
}

impl ToFfi<u8> for PortRangeModifier {
    fn to_ffi(&self) -> u8 {
        match *self {
            PortRangeModifier::Exclusive => ffi::pfvar::PF_OP_IRG as u8,
            PortRangeModifier::Inclusive => ffi::pfvar::PF_OP_RRG as u8,
            PortRangeModifier::Except => ffi::pfvar::PF_OP_XRG as u8,
        }
    }
}


// Implementations to convert types that are not ours into their FFI representation

impl CopyToFfi<ffi::pfvar::pf_addr_wrap> for IpNetwork {
    fn copy_to(&self, pf_addr_wrap: &mut ffi::pfvar::pf_addr_wrap) -> ::Result<()> {
        pf_addr_wrap.type_ = ffi::pfvar::PF_ADDR_ADDRMASK as u8;
        let a = unsafe { pf_addr_wrap.v.a.as_mut() };
        self.ip().copy_to(&mut a.addr)?;
        self.mask().copy_to(&mut a.mask)?;
        Ok(())
    }
}

impl CopyToFfi<ffi::pfvar::pf_addr> for IpAddr {
    fn copy_to(&self, pf_addr: &mut ffi::pfvar::pf_addr) -> ::Result<()> {
        match *self {
            IpAddr::V4(ip) => ip.copy_to(unsafe { pf_addr.pfa.v4.as_mut() }),
            IpAddr::V6(ip) => ip.copy_to(unsafe { pf_addr.pfa.v6.as_mut() }),
        }
    }
}

impl CopyToFfi<ffi::pfvar::in_addr> for Ipv4Addr {
    fn copy_to(&self, in_addr: &mut ffi::pfvar::in_addr) -> ::Result<()> {
        in_addr.s_addr = u32::from(*self).to_be();
        Ok(())
    }
}

impl CopyToFfi<ffi::pfvar::in6_addr> for Ipv6Addr {
    fn copy_to(&self, in6_addr: &mut ffi::pfvar::in6_addr) -> ::Result<()> {
        let segments = self.segments();
        let dst_segments = unsafe { in6_addr.__u6_addr.__u6_addr16.as_mut() };
        for (dst_segment, segment) in dst_segments.iter_mut().zip(segments.into_iter()) {
            *dst_segment = segment.to_be();
        }
        Ok(())
    }
}


impl ToFfi<u8> for bool {
    fn to_ffi(&self) -> u8 {
        if *self { 1 } else { 0 }
    }
}

/// Safely copy a Rust string into a raw buffer. Returning an error if `src` could not be
/// copied to the buffer.

impl<T: AsRef<str>> CopyToFfi<[i8]> for T {
    fn copy_to(&self, dst: &mut [i8]) -> ::Result<()> {
        let src_i8: &[i8] = unsafe { mem::transmute(self.as_ref().as_bytes()) };

        ensure!(src_i8.len() < dst.len(),
                ::ErrorKind::InvalidArgument("String does not fit destination"));
        ensure!(!src_i8.contains(&0),
                ::ErrorKind::InvalidArgument("String has null byte"));

        dst[..src_i8.len()].copy_from_slice(src_i8);
        // Terminate ffi string with null byte
        dst[src_i8.len()] = 0;
        Ok(())
    }
}
