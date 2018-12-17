// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::ffi;

/// Enum describing the kinds of rulesets
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RulesetKind {
    Filter,
    Redirect,
}

impl From<RulesetKind> for i32 {
    fn from(ruleset_kind: RulesetKind) -> Self {
        match ruleset_kind {
            RulesetKind::Filter => ffi::pfvar::PF_RULESET_FILTER as i32,
            RulesetKind::Redirect => ffi::pfvar::PF_RULESET_RDR as i32,
        }
    }
}
