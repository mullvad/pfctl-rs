// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use {ErrorKind, Result, ResultExt};
use conversion::{CopyTo, TryCopyTo};
use ffi;
use ipnetwork::IpNetwork;

use libc;

use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::vec::Vec;

mod addr_family;
pub use self::addr_family::*;

mod endpoint;
pub use self::endpoint::*;

mod ip;
pub use self::ip::*;

mod port;
pub use self::port::*;

mod interface;
pub use self::interface::*;

mod tcp_flags;
pub use self::tcp_flags::*;


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[derive(Builder)]
#[builder(setter(into))]
#[builder(build_fn(name = "build_internal"))]
pub struct FilterRule {
    action: RuleAction,
    #[builder(default)]
    direction: Direction,
    #[builder(default)]
    quick: bool,
    #[builder(default)]
    log: RuleLogSet,
    #[builder(default)]
    keep_state: StatePolicy,
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
    #[builder(default)]
    tcp_flags: TcpFlags,
}

impl FilterRuleBuilder {
    pub fn build(&self) -> Result<FilterRule> {
        self.build_internal().map_err(|e| ErrorKind::InvalidRuleCombination(e).into())
    }
}

impl FilterRule {
    /// Returns the `AddrFamily` this rule matches against. Returns an `InvalidRuleCombination`
    /// error if this rule has an invalid combination of address families.
    fn get_af(&self) -> Result<AddrFamily> {
        let endpoint_af = Self::compatible_af(self.from.get_af(), self.to.get_af())?;
        Self::compatible_af(self.af, endpoint_af)
    }

    fn compatible_af(af1: AddrFamily, af2: AddrFamily) -> Result<AddrFamily> {
        match (af1, af2) {
            (af1, af2) if af1 == af2 => Ok(af1),
            (af, AddrFamily::Any) => Ok(af),
            (AddrFamily::Any, af) => Ok(af),
            (af1, af2) => {
                let msg = format!("AddrFamily {} and {} are incompatible", af1, af2);
                bail!(ErrorKind::InvalidRuleCombination(msg));
            }
        }
    }

    /// Validates the combination of StatePolicy and Proto.
    fn validate_state_policy(&self) -> Result<StatePolicy> {
        match (self.keep_state, self.proto) {
            (StatePolicy::None, _) |
            (StatePolicy::Keep, _) |
            (StatePolicy::Modulate, Proto::Tcp) |
            (StatePolicy::SynProxy, Proto::Tcp) => Ok(self.keep_state),
            (state_policy, proto) => {
                let msg = format!(
                    "StatePolicy {:?} and protocol {:?} are incompatible",
                    state_policy,
                    proto
                );
                bail!(ErrorKind::InvalidRuleCombination(msg));
            }
        }
    }
}

impl TryCopyTo<ffi::pfvar::pf_rule> for FilterRule {
    fn copy_to(&self, pf_rule: &mut ffi::pfvar::pf_rule) -> Result<()> {
        pf_rule.action = self.action.into();
        pf_rule.direction = self.direction.into();
        pf_rule.quick = self.quick as u8;
        pf_rule.log = (&self.log).into();
        pf_rule.keep_state = self.validate_state_policy()?.into();
        pf_rule.flags = (&self.tcp_flags.check).into();
        pf_rule.flagset = (&self.tcp_flags.mask).into();
        self.interface
            .copy_to(&mut pf_rule.ifname)
            .chain_err(|| ErrorKind::InvalidArgument("Incompatible interface name"))?;
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

    #[test]
    fn state_policy_correct_default() {
        assert_eq!(
            StatePolicy::None,
            FilterRuleBuilder::default()
                .action(RuleAction::Pass)
                .build()
                .unwrap()
                .validate_state_policy()
                .unwrap()
        );
    }

    #[test]
    fn state_policy_none() {
        assert_eq!(
            StatePolicy::None,
            FilterRuleBuilder::default()
                .action(RuleAction::Pass)
                .keep_state(StatePolicy::None)
                .proto(Proto::Tcp)
                .build()
                .unwrap()
                .validate_state_policy()
                .unwrap()
        );
    }

    #[test]
    fn state_policy_keep() {
        assert_eq!(
            StatePolicy::Keep,
            FilterRuleBuilder::default()
                .action(RuleAction::Pass)
                .keep_state(StatePolicy::Keep)
                .proto(Proto::Tcp)
                .build()
                .unwrap()
                .validate_state_policy()
                .unwrap()
        );
    }

    #[test]
    fn state_policy_modulate() {
        assert_eq!(
            StatePolicy::Modulate,
            FilterRuleBuilder::default()
                .action(RuleAction::Pass)
                .keep_state(StatePolicy::Modulate)
                .proto(Proto::Tcp)
                .build()
                .unwrap()
                .validate_state_policy()
                .unwrap()
        );
    }

    #[test]
    fn state_policy_incompatible_modulate() {
        assert!(
            FilterRuleBuilder::default()
                .action(RuleAction::Pass)
                .keep_state(StatePolicy::Modulate)
                .proto(Proto::Udp)
                .build()
                .unwrap()
                .validate_state_policy()
                .is_err()
        );
    }

    #[test]
    fn state_policy_synproxy() {
        assert_eq!(
            StatePolicy::SynProxy,
            FilterRuleBuilder::default()
                .action(RuleAction::Pass)
                .keep_state(StatePolicy::SynProxy)
                .proto(Proto::Tcp)
                .build()
                .unwrap()
                .validate_state_policy()
                .unwrap()
        );
    }

    #[test]
    fn state_policy_incompatible_synproxy() {
        assert!(
            FilterRuleBuilder::default()
                .action(RuleAction::Pass)
                .keep_state(StatePolicy::SynProxy)
                .proto(Proto::Udp)
                .build()
                .unwrap()
                .validate_state_policy()
                .is_err()
        );
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


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    Any,
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
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
            Proto::Udp => libc::IPPROTO_UDP as u8,
            Proto::Icmp => libc::IPPROTO_ICMP as u8,
            Proto::IcmpV6 => libc::IPPROTO_ICMPV6 as u8,
        }
    }
}



#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatePolicy {
    None,
    Keep,
    Modulate,
    SynProxy,
}

impl Default for StatePolicy {
    fn default() -> Self {
        StatePolicy::None
    }
}

impl From<StatePolicy> for u8 {
    fn from(state_policy: StatePolicy) -> Self {
        match state_policy {
            StatePolicy::None => 0,
            StatePolicy::Keep => ffi::pfvar::PF_STATE_NORMAL as u8,
            StatePolicy::Modulate => ffi::pfvar::PF_STATE_MODULATE as u8,
            StatePolicy::SynProxy => ffi::pfvar::PF_STATE_SYNPROXY as u8,
        }
    }
}




/// Enum describing logging options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleLog {
    /// Log all packets, but only initial packet for connections with state
    /// Can be omitted if IncludeMatchingState set
    ExcludeMatchingState,
    /// Log all packets including ones matching state
    IncludeMatchingState,
    /// Log user id and group id that owns the local socket
    SocketOwner,
}

impl From<RuleLog> for u8 {
    fn from(rule_log: RuleLog) -> Self {
        match rule_log {
            RuleLog::ExcludeMatchingState => ffi::pfvar::PF_LOG as u8,
            RuleLog::IncludeMatchingState => ffi::pfvar::PF_LOG_ALL as u8,
            RuleLog::SocketOwner => ffi::pfvar::PF_LOG_SOCKET_LOOKUP as u8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct RuleLogSet(Vec<RuleLog>);

impl RuleLogSet {
    pub fn new(set: &[RuleLog]) -> Self {
        RuleLogSet(set.to_vec())
    }
}

impl From<RuleLog> for RuleLogSet {
    fn from(rule_log: RuleLog) -> Self {
        RuleLogSet(vec![rule_log])
    }
}

impl<'a> From<&'a RuleLogSet> for u8 {
    fn from(set: &RuleLogSet) -> Self {
        set.0
            .iter()
            .fold(0, |acc, &x| (acc | u8::from(x)))
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
    fn copy_to(&self, dst: &mut [i8]) -> Result<()> {
        let src_i8: &[i8] = unsafe { mem::transmute(self.as_ref().as_bytes()) };

        ensure!(
            src_i8.len() < dst.len(),
            ErrorKind::InvalidArgument("String does not fit destination")
        );
        ensure!(
            !src_i8.contains(&0),
            ErrorKind::InvalidArgument("String has null byte")
        );

        dst[..src_i8.len()].copy_from_slice(src_i8);
        // Terminate ffi string with null byte
        dst[src_i8.len()] = 0;
        Ok(())
    }
}
