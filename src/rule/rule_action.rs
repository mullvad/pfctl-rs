// Copyright 2017 Amagicom AB.
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
    Drop,
}

impl From<FilterRuleAction> for u8 {
    fn from(rule_action: FilterRuleAction) -> Self {
        match rule_action {
            FilterRuleAction::Pass => ffi::pfvar::PF_PASS as u8,
            FilterRuleAction::Drop => ffi::pfvar::PF_DROP as u8,
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
