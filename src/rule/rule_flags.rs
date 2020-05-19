// Copyright 2020 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleFlag {
    Drop,
    ReturnRst,
    Fragment,
    ReturnIcmp,
    Return,
    NoSync,
    SrcTrack,
    RuleSrcTrack,
    SetDelay,
}

pub const PFRULE_DROP: u8 = 0;
pub const PFRULE_RETURNRST: u8 = 1;
pub const PFRULE_FRAGMENT: u8 = 0x2;
pub const PFRULE_RETURNICMP: u8 = 0x4;
pub const PFRULE_RETURN: u8 = 0x8;
pub const PFRULE_NOSYNC: u8 = 0x10;
pub const PFRULE_SRCTRACK: u8 = 0x20;
pub const PFRULE_RULESRCTRACK: u8 = 0x40;
pub const PFRULE_SETDELAY: u8 = 0x80;

impl Default for RuleFlag {
    fn default() -> Self {
        RuleFlag::Drop
    }
}

impl From<RuleFlag> for u32 {
    fn from(rule_flag: RuleFlag) -> Self {
        match rule_flag {
            RuleFlag::Drop => PFRULE_DROP as u32,
            RuleFlag::ReturnRst => PFRULE_RETURNRST as u32,
            RuleFlag::Fragment => PFRULE_FRAGMENT as u32,
            RuleFlag::ReturnIcmp => PFRULE_RETURNICMP as u32,
            RuleFlag::Return => PFRULE_RETURN as u32,
            RuleFlag::NoSync => PFRULE_NOSYNC as u32,
            RuleFlag::SrcTrack => PFRULE_SRCTRACK as u32,
            RuleFlag::RuleSrcTrack => PFRULE_RULESRCTRACK as u32,
            RuleFlag::SetDelay => PFRULE_SETDELAY as u32,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct RuleFlagSet(Vec<RuleFlag>);

impl RuleFlagSet {
    pub fn new(set: &[RuleFlag]) -> Self {
        RuleFlagSet(set.to_vec())
    }
}

impl From<RuleFlag> for RuleFlagSet {
    fn from(rule_flag: RuleFlag) -> Self {
        RuleFlagSet(vec![rule_flag])
    }
}

impl<'a> From<&'a RuleFlagSet> for u32 {
    fn from(set: &RuleFlagSet) -> Self {
        set.0.iter().fold(0, |acc, &x| (acc | u32::from(x)))
    }
}
