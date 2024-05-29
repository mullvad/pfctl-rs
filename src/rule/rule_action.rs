// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::ffi;

/// Enum describing what should happen to a packet that matches a filter rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FilterRuleAction {
    Pass,
    Drop(DropAction),
}

/// Action to take for [`FilterRuleAction::Drop`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DropAction {
    /// Silently drop the packet.
    Drop,
    /// Return a TCP RST or ICMP reject packet.
    Return,
    /// Return a TCP RST packet.
    ReturnRst,
    /// Return an ICMP reject packet.
    ReturnIcmp,
}

impl FilterRuleAction {
    pub fn rule_flags(&self) -> u32 {
        match *self {
            FilterRuleAction::Pass => 0u32,
            FilterRuleAction::Drop(action) => action.into(),
        }
    }
}

impl From<FilterRuleAction> for u8 {
    fn from(rule_action: FilterRuleAction) -> Self {
        match rule_action {
            FilterRuleAction::Pass => ffi::pfvar::PF_PASS as u8,
            FilterRuleAction::Drop(_) => ffi::pfvar::PF_DROP as u8,
        }
    }
}

impl From<DropAction> for u32 {
    fn from(drop_action: DropAction) -> Self {
        use crate::ffi::pfvar::*;
        match drop_action {
            DropAction::Drop => PFRULE_DROP,
            DropAction::Return => PFRULE_RETURN,
            DropAction::ReturnRst => PFRULE_RETURNRST,
            DropAction::ReturnIcmp => PFRULE_RETURNICMP,
        }
    }
}

/// Enum describing what should happen to a packet that matches a redirect rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedirectRuleAction {
    Redirect,
    NoRedirect,
}

impl From<RedirectRuleAction> for u8 {
    fn from(rule_action: RedirectRuleAction) -> Self {
        match rule_action {
            RedirectRuleAction::Redirect => ffi::pfvar::PF_RDR as u8,
            RedirectRuleAction::NoRedirect => ffi::pfvar::PF_NORDR as u8,
        }
    }
}
