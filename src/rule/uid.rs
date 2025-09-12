// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{
    conversion::CopyTo,
    ffi::pfvar::{self, pf_rule_uid},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Id {
    Any,
    One(u32, IdUnaryModifier),
    Range(u32, u32, IdRangeModifier),
}

impl From<u32> for Id {
    fn from(uid: u32) -> Self {
        Id::One(uid, IdUnaryModifier::Equal)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uid(pub Id);

impl Default for Uid {
    fn default() -> Self {
        Uid(Id::Any)
    }
}

impl<T: Into<Id>> From<T> for Uid {
    fn from(id: T) -> Self {
        Uid(id.into())
    }
}

impl CopyTo<pf_rule_uid> for Uid {
    fn copy_to(&self, pf_rule_uid: &mut pf_rule_uid) {
        match self.0 {
            Id::Any => {
                pf_rule_uid.uid[0] = 0;
                pf_rule_uid.op = pfvar::PF_OP_NONE as u8;
            }

            Id::One(uid, modifier) => {
                pf_rule_uid.uid[0] = uid;
                pf_rule_uid.op = modifier.into();
            }

            Id::Range(start_uid, end_uid, modifier) => {
                pf_rule_uid.uid[0] = start_uid;
                pf_rule_uid.uid[1] = end_uid;
                pf_rule_uid.op = modifier.into();
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdUnaryModifier {
    Equal,
    NotEqual,
    Less,
    LessOrEqual,
    Greater,
    GreaterOrEqual,
}

impl From<IdUnaryModifier> for u8 {
    fn from(modifier: IdUnaryModifier) -> Self {
        match modifier {
            IdUnaryModifier::Equal => pfvar::PF_OP_EQ as u8,
            IdUnaryModifier::NotEqual => pfvar::PF_OP_NE as u8,
            IdUnaryModifier::Greater => pfvar::PF_OP_GT as u8,
            IdUnaryModifier::Less => pfvar::PF_OP_LT as u8,
            IdUnaryModifier::GreaterOrEqual => pfvar::PF_OP_GE as u8,
            IdUnaryModifier::LessOrEqual => pfvar::PF_OP_LE as u8,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdRangeModifier {
    Exclusive,
    Inclusive,
    Except,
}

impl From<IdRangeModifier> for u8 {
    fn from(modifier: IdRangeModifier) -> Self {
        match modifier {
            IdRangeModifier::Exclusive => pfvar::PF_OP_IRG as u8,
            IdRangeModifier::Inclusive => pfvar::PF_OP_RRG as u8,
            IdRangeModifier::Except => pfvar::PF_OP_XRG as u8,
        }
    }
}
