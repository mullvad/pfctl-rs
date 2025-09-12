// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::ffi;

/// Enum describing the kinds of anchors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AnchorKind {
    Filter,
    Nat,
    Redirect,
    Scrub,
}

impl From<AnchorKind> for u8 {
    fn from(anchor_kind: AnchorKind) -> u8 {
        match anchor_kind {
            AnchorKind::Filter => ffi::pfvar::PF_PASS as u8,
            AnchorKind::Nat => ffi::pfvar::PF_NAT as u8,
            AnchorKind::Redirect => ffi::pfvar::PF_RDR as u8,
            AnchorKind::Scrub => ffi::pfvar::PF_SCRUB as u8,
        }
    }
}
