// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

pub use super::uid::Id;
use crate::{
    conversion::CopyTo,
    ffi::pfvar::{pf_rule_gid, PF_OP_NONE},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Gid(pub Id);

impl Default for Gid {
    fn default() -> Self {
        Gid(Id::Any)
    }
}

impl<T: Into<Id>> From<T> for Gid {
    fn from(id: T) -> Self {
        Gid(id.into())
    }
}

impl CopyTo<pf_rule_gid> for Gid {
    fn copy_to(&self, pf_rule_gid: &mut pf_rule_gid) {
        match self.0 {
            Id::Any => {
                pf_rule_gid.gid[0] = 0;
                pf_rule_gid.op = PF_OP_NONE as u8;
            }

            Id::One(gid, modifier) => {
                pf_rule_gid.gid[0] = gid;
                pf_rule_gid.op = modifier.into();
            }

            Id::Range(start_gid, end_gid, modifier) => {
                pf_rule_gid.gid[0] = start_gid;
                pf_rule_gid.gid[1] = end_gid;
                pf_rule_gid.op = modifier.into();
            }
        }
    }
}
