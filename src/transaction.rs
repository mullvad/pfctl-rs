// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use {ErrorKind, Result, ResultExt};
use {FilterRule, RulesetKind};
use conversion::TryCopyTo;
use ffi;

use std::fs::File;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use utils;

#[derive(Debug)]
pub struct Transaction {
    file: File,
    ticket: u32,
    kind: RulesetKind,
    anchor: String,
}

impl Transaction {
    /// Returns a new `Transaction` if opening the PF device file succeeded.
    pub fn new(anchor: &str, kind: RulesetKind) -> Result<Self> {
        let file = utils::open_pf()?;
        let ticket = Self::get_ticket(file.as_raw_fd(), &anchor, kind)?;
        Ok(
            Transaction {
                file: file,
                ticket: ticket,
                kind: kind,
                anchor: anchor.to_owned(),
            },
        )
    }

    /// Commit transaction
    pub fn commit(&self) -> Result<()> {
        let mut pfioc_trans_e = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() };
        self.try_copy_to(&mut pfioc_trans_e)?;

        let mut trans_elements = [pfioc_trans_e];
        let mut pfioc_trans = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans>() };
        Self::setup_trans(&mut pfioc_trans, &mut trans_elements);

        ioctl_guard!(ffi::pf_commit_trans(self.fd(), &mut pfioc_trans))
    }

    /// Append an array of rules into transaction
    pub fn add_rules(&self, rules: &[FilterRule]) -> Result<()> {
        for rule in rules.iter() {
            self.add_rule(&rule)?;
        }
        Ok(())
    }

    /// Append single rule into transaction
    pub fn add_rule(&self, rule: &FilterRule) -> Result<()> {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };

        pfioc_rule.action = ffi::pfvar::PF_CHANGE_NONE as u32;
        pfioc_rule.pool_ticket = utils::get_pool_ticket(self.fd(), &self.anchor)?;
        rule.try_copy_to(&mut pfioc_rule.rule)?;
        self.try_copy_to(&mut pfioc_rule)?;

        ioctl_guard!(ffi::pf_add_rule(self.fd(), &mut pfioc_rule))
    }

    /// Internal function to obtain transaction ticket
    fn get_ticket(fd: RawFd, anchor: &str, kind: RulesetKind) -> Result<u32> {
        let mut pfioc_trans_e = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() };
        Self::setup_trans_element(&anchor, kind, &mut pfioc_trans_e)?;

        let mut trans_elements = [pfioc_trans_e];
        let mut pfioc_trans = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans>() };
        Self::setup_trans(&mut pfioc_trans, &mut trans_elements);

        ioctl_guard!(ffi::pf_begin_trans(fd, &mut pfioc_trans))?;

        Ok(trans_elements[0].ticket)
    }

    /// Internal function to wire up pfioc_trans and pfioc_trans_e
    fn setup_trans(pfioc_trans: &mut ffi::pfvar::pfioc_trans,
                   pfioc_trans_elements: &mut [ffi::pfvar::pfioc_trans_pfioc_trans_e]) {
        pfioc_trans.size = pfioc_trans_elements.len() as i32;
        pfioc_trans.esize = mem::size_of::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() as i32;
        pfioc_trans.array = pfioc_trans_elements.as_mut_ptr();
    }

    /// Internal function to initialize pfioc_trans_e
    fn setup_trans_element(anchor: &str,
                           kind: RulesetKind,
                           pfioc_trans_e: &mut ffi::pfvar::pfioc_trans_pfioc_trans_e)
                           -> Result<()> {
        pfioc_trans_e.rs_num = kind.into();
        anchor
            .try_copy_to(&mut pfioc_trans_e.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))
    }

    fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

impl TryCopyTo<ffi::pfvar::pfioc_trans_pfioc_trans_e> for Transaction {
    fn try_copy_to(&self, pfioc_trans_e: &mut ffi::pfvar::pfioc_trans_pfioc_trans_e) -> Result<()> {
        pfioc_trans_e.ticket = self.ticket;
        Self::setup_trans_element(&self.anchor, self.kind, pfioc_trans_e)
    }
}

impl TryCopyTo<ffi::pfvar::pfioc_rule> for Transaction {
    fn try_copy_to(&self, pfioc_rule: &mut ffi::pfvar::pfioc_rule) -> Result<()> {
        pfioc_rule.ticket = self.ticket;
        self.anchor
            .try_copy_to(&mut pfioc_rule.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))
    }
}
