// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use ffi;

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
