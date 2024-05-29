// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::ffi;

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
        set.0.iter().fold(0, |acc, &x| (acc | u8::from(x)))
    }
}
