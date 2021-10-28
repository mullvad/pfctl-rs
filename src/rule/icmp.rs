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
    /// Time Exceeded
    Timex(IcmpTimexCode),
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

/// ICMP Code fields for time exceeded ICMP packets ([`IcmpType::Timex`])
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum IcmpTimexCode {
    /// Time exceeded in transit
    Transit = 0,
    /// Time exceeded in reassembly
    Reassembly = 1,
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
            Timex(_) => 11,
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
            Timex(timex_code) => Some(*timex_code as u8),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_codes_are_expected() {
        // Expected values take from codes defined here:
        // https://man.openbsd.org/icmp.4

        assert_eq!(IcmpType::EchoRep.raw_code(), None);

        assert_eq!(
            IcmpType::Unreach(IcmpUnreachCode::NetUnreach).raw_code(),
            Some(0)
        );
        assert_eq!(
            IcmpType::Unreach(IcmpUnreachCode::HostUnreach).raw_code(),
            Some(1)
        );
        assert_eq!(
            IcmpType::Unreach(IcmpUnreachCode::ProtoUnreach).raw_code(),
            Some(2)
        );
        assert_eq!(
            IcmpType::Unreach(IcmpUnreachCode::PortUnreach).raw_code(),
            Some(3)
        );
        assert_eq!(
            IcmpType::Unreach(IcmpUnreachCode::NeedFrag).raw_code(),
            Some(4)
        );

        assert_eq!(IcmpType::EchoReq.raw_code(), None);

        assert_eq!(IcmpType::Timex(IcmpTimexCode::Transit).raw_code(), Some(0));
        assert_eq!(
            IcmpType::Timex(IcmpTimexCode::Reassembly).raw_code(),
            Some(1)
        );

        assert_eq!(IcmpType::Trace.raw_code(), None);

        assert_eq!(IcmpType::Icmp6(Icmp6Type::RouterSol).raw_code(), None);
        assert_eq!(IcmpType::Icmp6(Icmp6Type::RouterAdv).raw_code(), None);
        assert_eq!(IcmpType::Icmp6(Icmp6Type::NeighbrSol).raw_code(), None);
        assert_eq!(IcmpType::Icmp6(Icmp6Type::NeighbrAdv).raw_code(), None);
        assert_eq!(IcmpType::Icmp6(Icmp6Type::Redir).raw_code(), None);
    }

    #[test]
    fn all_types_are_expected() {
        // Expected values take from codes defined here:
        // https://man.openbsd.org/icmp.4

        assert_eq!(IcmpType::EchoRep.raw_type(), 0);

        assert_eq!(IcmpType::Unreach(IcmpUnreachCode::NetUnreach).raw_type(), 3);
        assert_eq!(
            IcmpType::Unreach(IcmpUnreachCode::HostUnreach).raw_type(),
            3
        );
        assert_eq!(
            IcmpType::Unreach(IcmpUnreachCode::ProtoUnreach).raw_type(),
            3
        );
        assert_eq!(
            IcmpType::Unreach(IcmpUnreachCode::PortUnreach).raw_type(),
            3
        );
        assert_eq!(IcmpType::Unreach(IcmpUnreachCode::NeedFrag).raw_type(), 3);

        assert_eq!(IcmpType::EchoReq.raw_type(), 8);

        assert_eq!(IcmpType::Timex(IcmpTimexCode::Transit).raw_type(), 11);
        assert_eq!(IcmpType::Timex(IcmpTimexCode::Reassembly).raw_type(), 11);

        assert_eq!(IcmpType::Trace.raw_type(), 30);

        assert_eq!(IcmpType::Icmp6(Icmp6Type::RouterSol).raw_type(), 133);
        assert_eq!(IcmpType::Icmp6(Icmp6Type::RouterAdv).raw_type(), 134);
        assert_eq!(IcmpType::Icmp6(Icmp6Type::NeighbrSol).raw_type(), 135);
        assert_eq!(IcmpType::Icmp6(Icmp6Type::NeighbrAdv).raw_type(), 136);
        assert_eq!(IcmpType::Icmp6(Icmp6Type::Redir).raw_type(), 137);
    }
}
