use conversion::{ToFfi, ApplyToFfi};
use ffi;

use libc;

use std::mem;
use std::net::Ipv4Addr;

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
    #[builder(default="Ipv4Addr::new(0, 0, 0, 0)")]
    from: Ipv4Addr,
    #[builder(default="Ipv4Addr::new(0, 0, 0, 0)")]
    to: Ipv4Addr,
}

impl FilterRule {
    // TODO(linus): Very ugly hack for now :(
    fn set_addr(addr: Ipv4Addr, pf_addr: &mut ffi::pfvar::pf_rule_addr) {
        unsafe {
            pf_addr.addr.type_ = ffi::pfvar::PF_ADDR_ADDRMASK as u8;
            pf_addr.addr
                .v
                .a
                .as_mut()
                .addr
                .pfa
                .v4
                .as_mut()
                .s_addr = addr.to_ffi();
            pf_addr.addr
                .v
                .a
                .as_mut()
                .mask
                .pfa
                .v4
                .as_mut()
                .s_addr = 0xffffffffu32;
        }
    }
}

impl ApplyToFfi<ffi::pfvar::pf_rule> for FilterRule {
    fn apply_to(&self, pf_rule: &mut ffi::pfvar::pf_rule) -> ::Result<()> {
        pf_rule.action = self.action.to_ffi();
        pf_rule.direction = self.direction.to_ffi();
        pf_rule.quick = self.quick.to_ffi();
        pf_rule.af = self.af.to_ffi();
        pf_rule.proto = self.proto.to_ffi();
        Self::set_addr(self.from, &mut pf_rule.src);
        Self::set_addr(self.to, &mut pf_rule.dst);
        Ok(())
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


// Implementations to convert types that are not ours into their FFI representation

impl ToFfi<u32> for Ipv4Addr {
    fn to_ffi(&self) -> u32 {
        unsafe { mem::transmute(self.octets()) }
    }
}

impl ToFfi<u8> for bool {
    fn to_ffi(&self) -> u8 {
        if *self { 1 } else { 0 }
    }
}
