// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use ffi;

/// Enum describing the kinds of anchors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorKind {
    Filter,
    Redirect,
}

impl From<AnchorKind> for u8 {
    fn from(anchor_kind: AnchorKind) -> u8 {
        match anchor_kind {
            AnchorKind::Filter => ffi::pfvar::PF_PASS as u8,
            AnchorKind::Redirect => ffi::pfvar::PF_RDR as u8,
        }
    }
}
