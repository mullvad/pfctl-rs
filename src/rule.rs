use ResultExt;
use conversion::{CopyTo, TryCopyTo};
use ffi;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};

use libc;

use std::fmt;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[derive(Builder)]
#[builder(setter(into))]
pub struct FilterRule {
    action: RuleAction,
    #[builder(default)]
    direction: Direction,
    #[builder(default)]
    quick: bool,
    #[builder(default)]
    interface: Interface,
    #[builder(default)]
    proto: Proto,
    #[builder(default)]
    af: AddrFamily,
    #[builder(default)]
    from: Endpoint,
    #[builder(default)]
    to: Endpoint,
}

impl FilterRule {
    /// Returns the `AddrFamily` this rule matches against. Returns an `InvalidRuleCombination`
    /// error if this rule has an invalid combination of address families.
    fn get_af(&self) -> ::Result<AddrFamily> {
        let endpoint_af = Self::compatible_af(self.from.get_af(), self.to.get_af())?;
        Self::compatible_af(self.af, endpoint_af)
    }

    fn compatible_af(af1: AddrFamily, af2: AddrFamily) -> ::Result<AddrFamily> {
        match (af1, af2) {
            (af1, af2) if af1 == af2 => Ok(af1),
            (af, AddrFamily::Any) => Ok(af),
            (AddrFamily::Any, af) => Ok(af),
            (af1, af2) => {
                let msg = format!("AddrFamily {} and {} are incompatible", af1, af2);
                bail!(::ErrorKind::InvalidRuleCombination(msg));
            }
        }
    }
}

impl TryCopyTo<ffi::pfvar::pf_rule> for FilterRule {
    fn copy_to(&self, pf_rule: &mut ffi::pfvar::pf_rule) -> ::Result<()> {
        pf_rule.action = self.action.into();
        pf_rule.direction = self.direction.into();
        pf_rule.quick = self.quick as u8;
        self.interface
            .copy_to(&mut pf_rule.ifname)
            .chain_err(|| ::ErrorKind::InvalidArgument("Incompatible interface name"),)?;
        pf_rule.proto = self.proto.into();
        pf_rule.af = self.get_af()?.into();
        self.from.copy_to(&mut pf_rule.src)?;
        self.to.copy_to(&mut pf_rule.dst)?;
        Ok(())
    }
}

#[cfg(test)]
mod filter_rule_tests {
    use super::*;

    lazy_static! {
        static ref IPV4: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
        static ref IPV6: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
    }

    #[test]
    fn correct_af_default() {
        let testee = FilterRuleBuilder::default().action(RuleAction::Pass).build().unwrap();
        assert_eq!(AddrFamily::Any, testee.get_af().unwrap());
    }

    #[test]
    fn af_incompatible_from_to() {
        let mut testee = FilterRuleBuilder::default();
        testee.action(RuleAction::Pass);
        let from4to6 = testee
            .from(*IPV4)
            .to(*IPV6)
            .build()
            .unwrap();
        let from6to4 = testee
            .from(*IPV6)
            .to(*IPV4)
            .build()
            .unwrap();
        assert!(from4to6.get_af().is_err());
        assert!(from6to4.get_af().is_err());
    }

    #[test]
    fn af_compatibility_ipv4() {
        let mut testee = FilterRuleBuilder::default();
        testee.action(RuleAction::Pass).from(*IPV4);
        assert_eq!(
            AddrFamily::Ipv4,
            testee
                .af(AddrFamily::Any)
                .build()
                .unwrap()
                .get_af()
                .unwrap()
        );
        assert_eq!(
            AddrFamily::Ipv4,
            testee
                .af(AddrFamily::Ipv4)
                .build()
                .unwrap()
                .get_af()
                .unwrap()
        );
        assert!(
            testee
                .af(AddrFamily::Ipv6)
                .build()
                .unwrap()
                .get_af()
                .is_err()
        );
    }

    #[test]
    fn af_compatibility_ipv6() {
        let mut testee = FilterRuleBuilder::default();
        testee.action(RuleAction::Pass).to(*IPV6);
        assert_eq!(
            AddrFamily::Ipv6,
            testee
                .af(AddrFamily::Any)
                .build()
                .unwrap()
                .get_af()
                .unwrap()
        );
        assert_eq!(
            AddrFamily::Ipv6,
            testee
                .af(AddrFamily::Ipv6)
                .build()
                .unwrap()
                .get_af()
                .unwrap()
        );
        assert!(
            testee
                .af(AddrFamily::Ipv4)
                .build()
                .unwrap()
                .get_af()
                .is_err()
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Endpoint(pub Ip, pub Port);

impl Endpoint {
    pub fn get_af(&self) -> AddrFamily {
        self.0.get_af()
    }
}

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

impl TryCopyTo<ffi::pfvar::pf_rule_addr> for Endpoint {
    fn copy_to(&self, pf_rule_addr: &mut ffi::pfvar::pf_rule_addr) -> ::Result<()> {
        let Endpoint(ref ip, ref port) = *self;
        ip.copy_to(&mut pf_rule_addr.addr);
        port.copy_to(unsafe { pf_rule_addr.xport.range.as_mut() })?;
        Ok(())
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Ip {
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
        IpNetwork::V6(Ipv6Network::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0).unwrap(),)
    }
}

impl Default for Ip {
    fn default() -> Self {
        Ip::Any
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

impl CopyTo<ffi::pfvar::pf_addr_wrap> for Ip {
    fn copy_to(&self, pf_addr_wrap: &mut ffi::pfvar::pf_addr_wrap) {
        match *self {
            Ip::Any => Self::any_ffi_repr().copy_to(pf_addr_wrap),
            Ip::Net(net) => net.copy_to(pf_addr_wrap),
        }
    }
}


/// Enum describing what should happen to a packet that matches a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleAction {
    Pass,
    Drop,
}

impl From<RuleAction> for u8 {
    fn from(rule_action: RuleAction) -> Self {
        match rule_action {
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

impl From<Direction> for u8 {
    fn from(direction: Direction) -> Self {
        match direction {
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

impl From<Proto> for u8 {
    fn from(proto: Proto) -> Self {
        match proto {
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

impl From<AddrFamily> for u8 {
    fn from(af: AddrFamily) -> Self {
        match af {
            AddrFamily::Any => ffi::pfvar::PF_UNSPEC as u8,
            AddrFamily::Ipv4 => ffi::pfvar::PF_INET as u8,
            AddrFamily::Ipv6 => ffi::pfvar::PF_INET6 as u8,
        }
    }
}

impl fmt::Display for AddrFamily {
    fn fmt(&self, f: &mut fmt::Formatter) -> ::std::result::Result<(), fmt::Error> {
        match *self {
                AddrFamily::Any => "any",
                AddrFamily::Ipv4 => "IPv4",
                AddrFamily::Ipv6 => "IPv6",
            }
            .fmt(f)
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

impl TryCopyTo<ffi::pfvar::pf_port_range> for Port {
    fn copy_to(&self, pf_port_range: &mut ffi::pfvar::pf_port_range) -> ::Result<()> {
        match *self {
            Port::Any => {
                pf_port_range.op = ffi::pfvar::PF_OP_NONE as u8;
                pf_port_range.port[0] = 0;
                pf_port_range.port[1] = 0;
            }
            Port::One(port, modifier) => {
                pf_port_range.op = modifier.into();
                // convert port range to network byte order
                pf_port_range.port[0] = port.to_be();
                pf_port_range.port[1] = 0;
            }
            Port::Range(start_port, end_port, modifier) => {
                ensure!(
                    start_port <= end_port,
                    ::ErrorKind::InvalidArgument("Lower port is greater than upper port.")
                );
                pf_port_range.op = modifier.into();
                // convert port range to network byte order
                pf_port_range.port[0] = start_port.to_be();
                pf_port_range.port[1] = end_port.to_be();
            }
        }
        Ok(())
    }
}

impl TryCopyTo<ffi::pfvar::pf_pool> for Port {
    fn copy_to(&self, pf_pool: &mut ffi::pfvar::pf_pool) -> ::Result<()> {
        match *self {
            Port::Any => {
                pf_pool.port_op = ffi::pfvar::PF_OP_NONE as u8;
                pf_pool.proxy_port[0] = 0;
                pf_pool.proxy_port[1] = 0;
            }
            Port::One(port, modifier) => {
                pf_pool.port_op = modifier.into();
                pf_pool.proxy_port[0] = port;
                pf_pool.proxy_port[1] = 0;
            }
            Port::Range(start_port, end_port, modifier) => {
                ensure!(
                    start_port <= end_port,
                    ::ErrorKind::InvalidArgument("Lower port is greater than upper port.")
                );
                pf_pool.port_op = modifier.into();
                pf_pool.proxy_port[0] = start_port;
                pf_pool.proxy_port[1] = end_port;
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

impl From<PortUnaryModifier> for u8 {
    fn from(modifier: PortUnaryModifier) -> Self {
        match modifier {
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

impl From<PortRangeModifier> for u8 {
    fn from(modifier: PortRangeModifier) -> Self {
        match modifier {
            PortRangeModifier::Exclusive => ffi::pfvar::PF_OP_IRG as u8,
            PortRangeModifier::Inclusive => ffi::pfvar::PF_OP_RRG as u8,
            PortRangeModifier::Except => ffi::pfvar::PF_OP_XRG as u8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Interface {
    Any,
    Name(String),
}

impl Default for Interface {
    fn default() -> Self {
        Interface::Any
    }
}

impl<T: AsRef<str>> From<T> for Interface {
    fn from(name: T) -> Self {
        Interface::Name(name.as_ref().to_owned())
    }
}

impl TryCopyTo<[i8]> for Interface {
    fn copy_to(&self, dst: &mut [i8]) -> ::Result<()> {
        match *self {
                Interface::Any => "",
                Interface::Name(ref name) => &name[..],
            }
            .copy_to(dst)
    }
}


// Implementations to convert types that are not ours into their FFI representation

impl CopyTo<ffi::pfvar::pf_addr_wrap> for IpNetwork {
    fn copy_to(&self, pf_addr_wrap: &mut ffi::pfvar::pf_addr_wrap) {
        pf_addr_wrap.type_ = ffi::pfvar::PF_ADDR_ADDRMASK as u8;
        let a = unsafe { pf_addr_wrap.v.a.as_mut() };
        self.ip().copy_to(&mut a.addr);
        self.mask().copy_to(&mut a.mask);
    }
}

impl CopyTo<ffi::pfvar::pf_addr> for IpAddr {
    fn copy_to(&self, pf_addr: &mut ffi::pfvar::pf_addr) {
        match *self {
            IpAddr::V4(ip) => ip.copy_to(unsafe { pf_addr.pfa.v4.as_mut() }),
            IpAddr::V6(ip) => ip.copy_to(unsafe { pf_addr.pfa.v6.as_mut() }),
        }
    }
}

impl CopyTo<ffi::pfvar::in_addr> for Ipv4Addr {
    fn copy_to(&self, in_addr: &mut ffi::pfvar::in_addr) {
        in_addr.s_addr = u32::from(*self).to_be();
    }
}

impl CopyTo<ffi::pfvar::in6_addr> for Ipv6Addr {
    fn copy_to(&self, in6_addr: &mut ffi::pfvar::in6_addr) {
        let segments = self.segments();
        let dst_segments = unsafe { in6_addr.__u6_addr.__u6_addr16.as_mut() };
        for (dst_segment, segment) in dst_segments.iter_mut().zip(segments.into_iter()) {
            *dst_segment = segment.to_be();
        }
    }
}

impl<T: AsRef<str>> TryCopyTo<[i8]> for T {
    /// Safely copy a Rust string into a raw buffer. Returning an error if the string could not be
    /// copied to the buffer.
    fn copy_to(&self, dst: &mut [i8]) -> ::Result<()> {
        let src_i8: &[i8] = unsafe { mem::transmute(self.as_ref().as_bytes()) };

        ensure!(
            src_i8.len() < dst.len(),
            ::ErrorKind::InvalidArgument("String does not fit destination")
        );
        ensure!(
            !src_i8.contains(&0),
            ::ErrorKind::InvalidArgument("String has null byte")
        );

        dst[..src_i8.len()].copy_from_slice(src_i8);
        // Terminate ffi string with null byte
        dst[src_i8.len()] = 0;
        Ok(())
    }
}
