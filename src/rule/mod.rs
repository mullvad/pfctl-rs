// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{
    conversion::{CopyTo, TryCopyTo},
    ffi, Error, ErrorInternal, Result,
};
use ipnetwork::IpNetwork;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ops::Deref,
};

mod addr_family;
pub use self::addr_family::*;

mod direction;
pub use self::direction::*;

mod endpoint;
pub use self::endpoint::*;

mod gid;
pub use self::gid::*;

mod icmp;
pub use self::icmp::*;

mod ip;
pub use self::ip::*;

mod proto;
pub use self::proto::*;

mod route;
pub use self::route::*;

mod port;
pub use self::port::*;

mod interface;
pub use self::interface::*;

mod state_policy;
pub use self::state_policy::*;

mod tcp_flags;
pub use self::tcp_flags::*;

mod rule_action;
pub use self::rule_action::*;

mod rule_log;
pub use self::rule_log::*;

mod uid;
pub use self::uid::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_builder::Builder)]
#[builder(setter(into))]
#[builder(build_fn(error = "Error"))]
pub struct FilterRule {
    action: FilterRuleAction,
    #[builder(default)]
    direction: Direction,
    #[builder(default)]
    quick: bool,
    #[builder(default)]
    log: RuleLogSet,
    #[builder(default)]
    route: Route,
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
    #[builder(default)]
    label: String,
    #[builder(default)]
    user: Uid,
    #[builder(default)]
    group: Gid,
    #[builder(default)]
    icmp_type: Option<IcmpType>,
}

impl FilterRule {
    /// Returns the `AddrFamily` this rule matches against. Returns an `InvalidRuleCombination`
    /// error if this rule has an invalid combination of address families.
    fn get_af(&self) -> Result<AddrFamily> {
        let endpoint_af = compatible_af(self.from.get_af(), self.to.get_af())?;
        compatible_af(self.af, endpoint_af)
    }

    /// Accessor for `route`
    pub fn get_route(&self) -> &Route {
        &self.route
    }

    /// Validates the combination of StatePolicy and Proto.
    fn validate_state_policy(&self) -> Result<StatePolicy> {
        match (self.keep_state, self.proto) {
            (StatePolicy::None, _)
            | (StatePolicy::Keep, _)
            | (StatePolicy::Modulate, Proto::Tcp)
            | (StatePolicy::SynProxy, Proto::Tcp) => Ok(self.keep_state),
            (state_policy, proto) => {
                let msg =
                    format!("StatePolicy {state_policy:?} and protocol {proto:?} are incompatible");
                Err(Error::from(ErrorInternal::InvalidRuleCombination(msg)))
            }
        }
    }
}

impl TryCopyTo<ffi::pfvar::pf_rule> for FilterRule {
    type Error = crate::Error;

    fn try_copy_to(&self, pf_rule: &mut ffi::pfvar::pf_rule) -> Result<()> {
        pf_rule.action = self.action.into();
        pf_rule.direction = self.direction.into();
        pf_rule.quick = self.quick as u8;
        pf_rule.log = (&self.log).into();
        pf_rule.rt = (&self.route).into();
        pf_rule.keep_state = self.validate_state_policy()?.into();
        pf_rule.flags = (&self.tcp_flags.check).into();
        pf_rule.flagset = (&self.tcp_flags.mask).into();
        pf_rule.rule_flag = self.action.rule_flags();

        self.interface.try_copy_to(&mut pf_rule.ifname)?;
        pf_rule.proto = self.proto.into();
        pf_rule.af = self.get_af()?.into();

        self.from.try_copy_to(&mut pf_rule.src)?;
        self.to.try_copy_to(&mut pf_rule.dst)?;
        self.label
            .try_copy_to(&mut pf_rule.label)
            .map_err(ErrorInternal::InvalidLabel)?;
        self.user.copy_to(&mut pf_rule.uid);
        self.group.copy_to(&mut pf_rule.gid);
        if let Some(icmp_type) = self.icmp_type {
            icmp_type.copy_to(pf_rule);
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_builder::Builder)]
#[builder(setter(into))]
#[builder(build_fn(error = "Error"))]
pub struct NatRule {
    action: NatRuleAction,
    #[builder(default)]
    interface: Interface,
    #[builder(default)]
    af: AddrFamily,
    #[builder(default)]
    from: Endpoint,
    #[builder(default)]
    to: Endpoint,
}

impl NatRule {
    /// Returns the `AddrFamily` this rule matches against. Returns an `InvalidRuleCombination`
    /// error if this rule has an invalid combination of address families.
    fn get_af(&self) -> Result<AddrFamily> {
        let endpoint_af = compatible_af(self.from.get_af(), self.to.get_af())?;
        if let Some(nat_to) = self.get_nat_to() {
            let nat_af = compatible_af(endpoint_af, nat_to.0.get_af())?;
            compatible_af(self.af, nat_af)
        } else {
            compatible_af(self.af, endpoint_af)
        }
    }

    /// Accessor for `nat_to`
    pub fn get_nat_to(&self) -> Option<NatEndpoint> {
        match self.action {
            NatRuleAction::Nat { nat_to } => Some(nat_to),
            NatRuleAction::NoNat => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatEndpoint(Endpoint);

impl Deref for NatEndpoint {
    type Target = Endpoint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Ip> for NatEndpoint {
    fn from(ip: Ip) -> Self {
        // Default NAT port range
        const NAT_LOWER_DEFAULT: u16 = 32768;
        const NAT_UPPER_DEFAULT: u16 = 49151;

        Self(Endpoint::new(
            ip,
            Port::Range(
                NAT_LOWER_DEFAULT,
                NAT_UPPER_DEFAULT,
                PortRangeModifier::Inclusive,
            ),
        ))
    }
}

impl Default for NatEndpoint {
    fn default() -> Self {
        Self::from(Ip::Any)
    }
}

impl From<Endpoint> for NatEndpoint {
    fn from(endpoint: Endpoint) -> Self {
        Self(endpoint)
    }
}

impl From<Ipv4Addr> for NatEndpoint {
    fn from(ip: Ipv4Addr) -> Self {
        Self::from(Ip::from(ip))
    }
}

impl From<Ipv6Addr> for NatEndpoint {
    fn from(ip: Ipv6Addr) -> Self {
        Self::from(Ip::from(ip))
    }
}

impl TryCopyTo<ffi::pfvar::pf_rule> for NatRule {
    type Error = crate::Error;

    fn try_copy_to(&self, pf_rule: &mut ffi::pfvar::pf_rule) -> Result<()> {
        pf_rule.action = self.action.into();
        self.interface.try_copy_to(&mut pf_rule.ifname)?;
        pf_rule.af = self.get_af()?.into();

        self.from.try_copy_to(&mut pf_rule.src)?;
        self.to.try_copy_to(&mut pf_rule.dst)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_builder::Builder)]
#[builder(setter(into))]
#[builder(build_fn(error = "Error"))]
pub struct RedirectRule {
    action: RedirectRuleAction,
    #[builder(default)]
    direction: Direction,
    #[builder(default)]
    quick: bool,
    #[builder(default)]
    log: RuleLogSet,
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
    label: String,
    #[builder(default)]
    user: Uid,
    #[builder(default)]
    group: Gid,
    redirect_to: Endpoint,
}

impl RedirectRule {
    /// Returns the `AddrFamily` this rule matches against. Returns an `InvalidRuleCombination`
    /// error if this rule has an invalid combination of address families.
    fn get_af(&self) -> Result<AddrFamily> {
        let endpoint_af = compatible_af(self.from.get_af(), self.to.get_af())?;
        let rdr_af = compatible_af(endpoint_af, self.redirect_to.get_af())?;
        compatible_af(self.af, rdr_af)
    }

    /// Accessor for `redirect_to`
    pub fn get_redirect_to(&self) -> Endpoint {
        self.redirect_to
    }
}

impl TryCopyTo<ffi::pfvar::pf_rule> for RedirectRule {
    type Error = crate::Error;

    fn try_copy_to(&self, pf_rule: &mut ffi::pfvar::pf_rule) -> Result<()> {
        pf_rule.action = self.action.into();
        pf_rule.direction = self.direction.into();
        pf_rule.quick = self.quick as u8;
        pf_rule.log = (&self.log).into();
        self.interface.try_copy_to(&mut pf_rule.ifname)?;
        pf_rule.proto = self.proto.into();
        pf_rule.af = self.get_af()?.into();

        self.from.try_copy_to(&mut pf_rule.src)?;
        self.to.try_copy_to(&mut pf_rule.dst)?;
        self.label
            .try_copy_to(&mut pf_rule.label)
            .map_err(ErrorInternal::InvalidLabel)?;
        self.user.copy_to(&mut pf_rule.uid);
        self.group.copy_to(&mut pf_rule.gid);

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, derive_builder::Builder)]
#[builder(setter(into))]
#[builder(build_fn(error = "Error"))]
pub struct ScrubRule {
    action: ScrubRuleAction,
    #[builder(default)]
    direction: Direction,
}

impl TryCopyTo<ffi::pfvar::pf_rule> for ScrubRule {
    type Error = crate::Error;

    fn try_copy_to(&self, pf_rule: &mut ffi::pfvar::pf_rule) -> Result<()> {
        pf_rule.action = self.action.into();
        pf_rule.direction = self.direction.into();
        Ok(())
    }
}

fn compatible_af(af1: AddrFamily, af2: AddrFamily) -> Result<AddrFamily> {
    match (af1, af2) {
        (af1, af2) if af1 == af2 => Ok(af1),
        (af, AddrFamily::Any) => Ok(af),
        (AddrFamily::Any, af) => Ok(af),
        (af1, af2) => {
            let msg = format!("AddrFamily {af1} and {af2} are incompatible");
            Err(Error::from(ErrorInternal::InvalidRuleCombination(msg)))
        }
    }
}

// Implementations to convert types that are not ours into their FFI representation

impl CopyTo<ffi::pfvar::pf_addr_wrap> for IpNetwork {
    fn copy_to(&self, pf_addr_wrap: &mut ffi::pfvar::pf_addr_wrap) {
        pf_addr_wrap.type_ = ffi::pfvar::PF_ADDR_ADDRMASK as u8;
        self.ip().copy_to(unsafe { &mut pf_addr_wrap.v.a.addr });
        self.mask().copy_to(unsafe { &mut pf_addr_wrap.v.a.mask });
    }
}

impl CopyTo<ffi::pfvar::pf_addr> for IpAddr {
    fn copy_to(&self, pf_addr: &mut ffi::pfvar::pf_addr) {
        match *self {
            IpAddr::V4(ip) => ip.copy_to(unsafe { &mut pf_addr.pfa._v4addr }),
            IpAddr::V6(ip) => ip.copy_to(unsafe { &mut pf_addr.pfa._v6addr }),
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
        for (dst_segment, segment) in dst_segments.iter_mut().zip(segments.iter()) {
            *dst_segment = segment.to_be();
        }
    }
}

impl<T: AsRef<str>> TryCopyTo<[i8]> for T {
    type Error = &'static str;

    /// Safely copy a Rust string into a raw buffer. Returning an error if the string could not
    /// be copied to the buffer.
    fn try_copy_to(&self, dst: &mut [i8]) -> std::result::Result<(), Self::Error> {
        let src_i8: &[i8] = unsafe { &*(self.as_ref().as_bytes() as *const _ as *const _) };

        if src_i8.len() >= dst.len() {
            return Err("Too long");
        }
        if src_i8.contains(&0) {
            return Err("Contains null byte");
        }

        dst[..src_i8.len()].copy_from_slice(src_i8);
        // Terminate ffi string with null byte
        dst[src_i8.len()] = 0;
        Ok(())
    }
}

#[cfg(test)]
mod filter_rule_tests {
    use super::*;

    #[test]
    fn correct_af_default() {
        let testee = FilterRuleBuilder::default()
            .action(FilterRuleAction::Pass)
            .build()
            .unwrap();
        assert_eq!(AddrFamily::Any, testee.get_af().unwrap());
    }

    #[test]
    fn af_incompatible_from_to() {
        let mut testee = FilterRuleBuilder::default();
        testee.action(FilterRuleAction::Pass);
        let from4to6 = testee
            .from(Ipv4Addr::UNSPECIFIED)
            .to(Ipv6Addr::UNSPECIFIED)
            .build()
            .unwrap();
        let from6to4 = testee
            .from(Ipv6Addr::UNSPECIFIED)
            .to(Ipv4Addr::UNSPECIFIED)
            .build()
            .unwrap();
        assert!(from4to6.get_af().is_err());
        assert!(from6to4.get_af().is_err());
    }

    #[test]
    fn af_compatibility_ipv4() {
        let mut testee = FilterRuleBuilder::default();
        testee
            .action(FilterRuleAction::Pass)
            .from(Ipv4Addr::UNSPECIFIED);
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
        assert!(testee
            .af(AddrFamily::Ipv6)
            .build()
            .unwrap()
            .get_af()
            .is_err());
    }

    #[test]
    fn af_compatibility_ipv6() {
        let mut testee = FilterRuleBuilder::default();
        testee
            .action(FilterRuleAction::Pass)
            .to(Ipv6Addr::UNSPECIFIED);
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
        assert!(testee
            .af(AddrFamily::Ipv4)
            .build()
            .unwrap()
            .get_af()
            .is_err());
    }

    #[test]
    fn state_policy_correct_default() {
        assert_eq!(
            StatePolicy::None,
            FilterRuleBuilder::default()
                .action(FilterRuleAction::Pass)
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
                .action(FilterRuleAction::Pass)
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
                .action(FilterRuleAction::Pass)
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
                .action(FilterRuleAction::Pass)
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
        assert!(FilterRuleBuilder::default()
            .action(FilterRuleAction::Pass)
            .keep_state(StatePolicy::Modulate)
            .proto(Proto::Udp)
            .build()
            .unwrap()
            .validate_state_policy()
            .is_err());
    }

    #[test]
    fn state_policy_synproxy() {
        assert_eq!(
            StatePolicy::SynProxy,
            FilterRuleBuilder::default()
                .action(FilterRuleAction::Pass)
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
        assert!(FilterRuleBuilder::default()
            .action(FilterRuleAction::Pass)
            .keep_state(StatePolicy::SynProxy)
            .proto(Proto::Udp)
            .build()
            .unwrap()
            .validate_state_policy()
            .is_err());
    }
}
