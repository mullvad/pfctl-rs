// Copyright 2021 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// ICMP type (and code). Used to match a rule against an ICMP packets `type` and `code` fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum IcmpType {
    /// Echo reply.
    EchoRep,
    /// Destination unreachable
    Unreach(IcmpUnreachCode),
    /// Echo request.
    EchoReq,
    /// Traceroute.
    Trace,
    /// ICMPv6
    Icmp6(Icmp6Type),
}

/// ICMP code fields for destination unreachable ICMP packet's ([`IcmpType::Unreach`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum IcmpUnreachCode {
    /// Network unreachable.
    NetUnreach = 0,
    /// Host unreachable.
    HostUnreach = 1,
    /// Protocol unreachable.
    ProtoUnreach = 2,
    /// Port unreachable.
    PortUnreach = 3,
    /// Fragmentation needed but DF bit set.
    NeedFrag = 4,
}

/// Values for the `type` field in ICMPv6 packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum Icmp6Type {
    /// Router solicitation.
    RouterSol = 133,
    /// Router advertisement.
    RouterAdv = 134,
    /// Neighbor solicitation.
    NeighbrSol = 135,
    /// Neighbor advertisement.
    NeighbrAdv = 136,
    /// Shorter route exists
    Redir = 137,
}

impl IcmpType {
    /// Returns the FFI representation for this ICMP type
    fn raw_type(&self) -> u8 {
        use IcmpType::*;
        match self {
            EchoRep => 0,
            Unreach(_) => 3,
            EchoReq => 8,
            Trace => 30,
            Icmp6(icmp6_type) => *icmp6_type as u8,
        }
    }

    /// Returns the FFI representation of the code for this ICMP type.
    /// Returns `None` if this ICMP type does not use the code field.
    fn raw_code(&self) -> Option<u8> {
        use IcmpType::*;
        match self {
            Unreach(unreach_code) => Some(*unreach_code as u8),
            _ => None,
        }
    }
}

impl crate::conversion::CopyTo<crate::ffi::pfvar::pf_rule> for IcmpType {
    fn copy_to(&self, pf_rule: &mut crate::ffi::pfvar::pf_rule) {
        // The field should be set to one higher than the constants.
        // See OpenBSD implementation of the `pfctl` CLI tool for reference.
        pf_rule.type_ = self.raw_type() + 1;
        pf_rule.code = match self.raw_code() {
            Some(raw_code) => raw_code + 1,
            None => 0,
        };
    }
}
