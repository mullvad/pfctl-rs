// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use {ErrorKind, Result, ResultExt};
use {FilterRule, RedirectRule, RulesetKind};
use conversion::{CopyTo, TryCopyTo};
use ffi;
use std::collections::HashMap;

use std::fs::File;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use utils;

/// Structure that allows to manipulate rules in batches
#[derive(Debug)]
pub struct Transaction {
    file: File,
    change_by_anchor: HashMap<String, AnchorChange>,
}

impl Transaction {
    /// Returns a new `Transaction` if opening the PF device file succeeded.
    pub fn new() -> Result<Self> {
        Ok(
            Transaction {
                file: utils::open_pf()?,
                change_by_anchor: HashMap::new(),
            },
        )
    }

    /// Add change into transaction replacing the prior change registered for corresponding anchor
    /// if any.
    pub fn add_change(&mut self, anchor_change: AnchorChange) {
        self.change_by_anchor.insert(anchor_change.anchor.clone(), anchor_change);
    }

    /// Convenience method to add multiple changes into Transaction.
    pub fn add_changes(&mut self, change_by_anchor: Vec<AnchorChange>) {
        for anchor_change in change_by_anchor {
            self.add_change(anchor_change);
        }
    }

    /// Commit transaction
    pub fn commit(&self) -> Result<()> {
        let mut pfioc_trans = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans>() };

        let all_changes = self.change_by_anchor.values().collect::<Vec<_>>();
        let filter_changes =
            all_changes.iter().filter(|c| c.filter_rules.is_some()).collect::<Vec<_>>();
        let redirect_changes =
            all_changes.iter().filter(|c| c.redirect_rules.is_some()).collect::<Vec<_>>();

        let mut pfioc_elements = filter_changes
            .iter()
            .map(|c| Self::new_trans_element(&c.anchor, RulesetKind::Filter))
            .chain(
                redirect_changes
                    .iter()
                    .map(|c| Self::new_trans_element(&c.anchor, RulesetKind::Redirect),),
            )
            .collect::<Result<Vec<_>>>()?;

        Self::setup_trans(&mut pfioc_trans, pfioc_elements.as_mut_slice());

        // fill in array of pfioc_trans_e with tickets
        ioctl_guard!(ffi::pf_begin_trans(self.fd(), &mut pfioc_trans))?;

        // register all rules in this transaction with firewall
        let mut pfioc_element_iterator = pfioc_elements.iter();
        for (change, pfioc_trans_e) in filter_changes.iter().zip(pfioc_element_iterator.by_ref()) {
            self.add_filter_rules(
                    &change.anchor,
                    change.filter_rules.as_ref().unwrap(),
                    pfioc_trans_e.ticket,
                )?;
        }

        for (change, pfioc_trans_e) in redirect_changes.iter().zip(pfioc_element_iterator.by_ref()) {
            self.add_redirect_rules(
                    &change.anchor,
                    change.redirect_rules.as_ref().unwrap(),
                    pfioc_trans_e.ticket,
                )?;
        }

        // commit transaction
        ioctl_guard!(ffi::pf_commit_trans(self.fd(), &mut pfioc_trans))
    }

    /// Internal function to wire up pfioc_trans and pfioc_trans_e
    fn setup_trans(pfioc_trans: &mut ffi::pfvar::pfioc_trans,
                   pfioc_trans_elements: &mut [ffi::pfvar::pfioc_trans_pfioc_trans_e]) {
        pfioc_trans.size = pfioc_trans_elements.len() as i32;
        pfioc_trans.esize = mem::size_of::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() as i32;
        pfioc_trans.array = pfioc_trans_elements.as_mut_ptr();
    }

    /// Internal function to initialize pfioc_trans_e
    fn new_trans_element(anchor: &str,
                         ruleset_kind: RulesetKind)
                         -> Result<ffi::pfvar::pfioc_trans_pfioc_trans_e> {
        let mut pfioc_trans_e = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() };
        pfioc_trans_e.rs_num = ruleset_kind.into();
        anchor
            .try_copy_to(&mut pfioc_trans_e.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
        Ok(pfioc_trans_e)
    }

    /// Internal function add single filter rule into transaction
    fn add_filter_rule(&self, anchor: &str, rule: &FilterRule, ticket: u32) -> Result<()> {
        // fill in rule information
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        pfioc_rule.action = ffi::pfvar::PF_CHANGE_NONE as u32;
        pfioc_rule.pool_ticket = utils::get_pool_ticket(self.fd(), &anchor)?;
        rule.try_copy_to(&mut pfioc_rule.rule)?;

        // fill in ticket with ticket associated with transaction
        pfioc_rule.ticket = ticket;
        anchor
            .try_copy_to(&mut pfioc_rule.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;

        // add rule into transaction
        ioctl_guard!(ffi::pf_add_rule(self.fd(), &mut pfioc_rule))
    }

    /// Internal function to add a batch of filter rules into transaction
    fn add_filter_rules(&self, anchor: &str, rules: &[FilterRule], ticket: u32) -> Result<()> {
        for rule in rules.iter() {
            self.add_filter_rule(anchor, rule, ticket)?;
        }
        Ok(())
    }

    /// Internal function to add single redirect rule into transaction
    fn add_redirect_rule(&self, anchor: &str, rule: &RedirectRule, ticket: u32) -> Result<()> {
        // register redirect address in newly created address pool
        let redirect_to = rule.get_redirect_to();
        let mut pfioc_pooladdr = unsafe { mem::zeroed::<ffi::pfvar::pfioc_pooladdr>() };
        ioctl_guard!(ffi::pf_begin_addrs(self.fd(), &mut pfioc_pooladdr))?;
        redirect_to.ip().copy_to(&mut pfioc_pooladdr.addr.addr);
        ioctl_guard!(ffi::pf_add_addr(self.fd(), &mut pfioc_pooladdr))?;

        // prepare pfioc_rule
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        anchor.try_copy_to(&mut pfioc_rule.anchor[..])?;
        rule.try_copy_to(&mut pfioc_rule.rule)?;

        // copy address pool in pf_rule
        let redirect_pool = redirect_to.ip().to_pool_addr_list();
        pfioc_rule.rule.rpool.list = unsafe { redirect_pool.to_palist() };
        redirect_to.port().try_copy_to(&mut pfioc_rule.rule.rpool)?;

        // set tickets
        pfioc_rule.pool_ticket = pfioc_pooladdr.ticket;
        pfioc_rule.ticket = ticket;

        // add rule into transaction
        ioctl_guard!(ffi::pf_add_rule(self.fd(), &mut pfioc_rule))
    }

    /// Internal function to add a batch of redirect rules into transaction
    fn add_redirect_rules(&self, anchor: &str, rules: &[RedirectRule], ticket: u32) -> Result<()> {
        for rule in rules.iter() {
            self.add_redirect_rule(anchor, rule, ticket)?;
        }
        Ok(())
    }

    fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}


/// Structure that describes anchor rules manipulation allowing for targeted changes in anchors.
/// The rules set to this structure will replace the active rules by transaction.
/// Not setting either of rules will leave active rules untouched by transaction.
/// In contrast, setting an empty vector for either of rules will remove the corresponding rules.
#[derive(Debug)]
pub struct AnchorChange {
    pub anchor: String,
    pub filter_rules: Option<Vec<FilterRule>>,
    pub redirect_rules: Option<Vec<RedirectRule>>,
}

impl AnchorChange {
    /// Returns an empty changeset for corresponding anchor
    pub fn new(anchor: &str) -> Self {
        AnchorChange {
            anchor: anchor.to_owned(),
            filter_rules: None,
            redirect_rules: None,
        }
    }

    pub fn set_filter_rules(&mut self, rules: Vec<FilterRule>) {
        self.filter_rules = Some(rules);
    }

    pub fn set_redirect_rules(&mut self, rules: Vec<RedirectRule>) {
        self.redirect_rules = Some(rules);
    }
}
