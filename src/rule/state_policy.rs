// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::ffi;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StatePolicy {
    #[default]
    None,
    Keep,
    Modulate,
    SynProxy,
}

impl From<StatePolicy> for u8 {
    fn from(state_policy: StatePolicy) -> Self {
        match state_policy {
            StatePolicy::None => 0,
            StatePolicy::Keep => ffi::pfvar::PF_STATE_NORMAL as u8,
            StatePolicy::Modulate => ffi::pfvar::PF_STATE_MODULATE as u8,
            StatePolicy::SynProxy => ffi::pfvar::PF_STATE_SYNPROXY as u8,
        }
    }
}
