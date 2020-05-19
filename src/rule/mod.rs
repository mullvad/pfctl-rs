// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{
    conversion::{CopyTo, TryCopyTo},
    ffi, ErrorKind, Result, ResultExt,
};
use derive_builder::Builder;
use ipnetwork::IpNetwork;
use std::{
    mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

mod addr_family;
pub use self::addr_family::*;

mod direction;
pub use self::direction::*;

mod endpoint;
pub use self::endpoint::*;

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

mod rule_flags;
pub use self::rule_flags::*;

mod rule_log;
pub use self::rule_log::*;


#[derive(Debug, Clone, PartialEq, Eq, Hash, Builder)]
#[builder(setter(into))]
#[builder(build_fn(name = "build_internal"))]
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
    rule_flag: RuleFlagSet,
    #[builder(default)]
    label: String,
}

impl FilterRuleBuilder {
    pub fn build(&self) -> Result<FilterRule> {
        self.build_internal()
            .map_err(|e| ErrorKind::InvalidRuleCombination(e).into())
    }
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
                let msg = format!(
                    "StatePolicy {:?} and protocol {:?} are incompatible",
                    state_policy, proto
                );
                bail!(ErrorKind::InvalidRuleCombination(msg));
            }
        }
    }
}

impl TryCopyTo<ffi::pfvar::pf_rule> for FilterRule {
    fn try_copy_to(&self, pf_rule: &mut ffi::pfvar::pf_rule) -> Result<()> {
        pf_rule.action = self.action.into();
        pf_rule.direction = self.direction.into();
        pf_rule.quick = self.quick as u8;
        pf_rule.log = (&self.log).into();
        pf_rule.rt = (&self.route).into();
        pf_rule.keep_state = self.validate_state_policy()?.into();
        pf_rule.flags = (&self.tcp_flags.check).into();
        pf_rule.flagset = (&self.tcp_flags.mask).into();
        pf_rule.rule_flag = (&self.rule_flag).into();
        self.interface
            .try_copy_to(&mut pf_rule.ifname)
            .chain_err(|| ErrorKind::InvalidArgument("Incompatible interface name"))?;
        pf_rule.proto = self.proto.into();
        pf_rule.af = self.get_af()?.into();

        self.from.try_copy_to(&mut pf_rule.src)?;
        self.to.try_copy_to(&mut pf_rule.dst)?;
        self.label.try_copy_to(&mut pf_rule.label)?;

        Ok(())
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Hash, Builder)]
#[builder(setter(into))]
#[builder(build_fn(name = "build_internal"))]
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
    redirect_to: Endpoint,
}

impl RedirectRuleBuilder {
    pub fn build(&self) -> Result<RedirectRule> {
        self.build_internal()
            .map_err(|e| ErrorKind::InvalidRuleCombination(e).into())
    }
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
    fn try_copy_to(&self, pf_rule: &mut ffi::pfvar::pf_rule) -> Result<()> {
        pf_rule.action = self.action.into();
        pf_rule.direction = self.direction.into();
        pf_rule.quick = self.quick as u8;
        pf_rule.log = (&self.log).into();
        self.interface
            .try_copy_to(&mut pf_rule.ifname)
            .chain_err(|| ErrorKind::InvalidArgument("Incompatible interface name"))?;
        pf_rule.proto = self.proto.into();
        pf_rule.af = self.get_af()?.into();

        self.from.try_copy_to(&mut pf_rule.src)?;
        self.to.try_copy_to(&mut pf_rule.dst)?;
        self.label.try_copy_to(&mut pf_rule.label)?;

        Ok(())
    }
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
            IpAddr::V4(ip) => ip.copy_to(unsafe { &mut pf_addr.pfa.v4 }),
            IpAddr::V6(ip) => ip.copy_to(unsafe { &mut pf_addr.pfa.v6 }),
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
    /// Safely copy a Rust string into a raw buffer. Returning an error if the string could not
    /// be copied to the buffer.
    fn try_copy_to(&self, dst: &mut [i8]) -> Result<()> {
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
