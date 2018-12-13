// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::conversion::TryCopyTo;
use crate::ffi;
use crate::{ErrorKind, Result, ResultExt};
use crate::{FilterRule, PoolAddrList, RedirectRule, RulesetKind};
use std::collections::HashMap;

use crate::utils;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};

/// Structure that allows to manipulate rules in batches
#[derive(Debug)]
pub struct Transaction {
    change_by_anchor: HashMap<String, AnchorChange>,
}

impl Transaction {
    /// Returns new `Transaction`
    pub fn new() -> Self {
        Transaction {
            change_by_anchor: HashMap::new(),
        }
    }

    /// Add change into transaction replacing the prior change registered for corresponding
    /// anchor if any.
    pub fn add_change(&mut self, anchor_name: &str, anchor_change: AnchorChange) {
        self.change_by_anchor
            .insert(anchor_name.to_owned(), anchor_change);
    }

    /// Commit transaction and consume itself
    pub fn commit(mut self) -> Result<()> {
        let pf_file = utils::open_pf()?;
        let fd = pf_file.as_raw_fd();
        let mut pfioc_trans = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans>() };

        // partition changes by ruleset kind
        let filter_changes: Vec<(String, Vec<FilterRule>)> = self
            .change_by_anchor
            .iter_mut()
            .filter_map(|(anchor, change)| {
                change
                    .filter_rules
                    .take()
                    .map(|rules| (anchor.clone(), rules))
            })
            .collect();
        let redirect_changes: Vec<(String, Vec<RedirectRule>)> = self
            .change_by_anchor
            .iter_mut()
            .filter_map(|(anchor, change)| {
                change
                    .redirect_rules
                    .take()
                    .map(|rules| (anchor.clone(), rules))
            })
            .collect();

        // create one transaction element for each unique combination of anchor name and
        // `RulesetKind` and order them so elements for filter rules go first followed by redirect
        // rules
        let mut pfioc_elements: Vec<ffi::pfvar::pfioc_trans_pfioc_trans_e> =
            filter_changes
                .iter()
                .map(|&(ref anchor, _)| Self::new_trans_element(&anchor, RulesetKind::Filter))
                .chain(redirect_changes.iter().map(|&(ref anchor, _)| {
                    Self::new_trans_element(&anchor, RulesetKind::Redirect)
                }))
                .collect::<Result<_>>()?;
        Self::setup_trans(&mut pfioc_trans, pfioc_elements.as_mut_slice());

        // get tickets
        ioctl_guard!(ffi::pf_begin_trans(fd, &mut pfioc_trans))?;

        // create iterator for tickets
        let mut ticket_iterator = pfioc_elements.iter().map(|e| e.ticket);

        // add filter rules into transaction
        for ((anchor_name, filter_rules), ticket) in
            filter_changes.into_iter().zip(ticket_iterator.by_ref())
        {
            for filter_rule in filter_rules.iter() {
                Self::add_filter_rule(fd, &anchor_name, filter_rule, ticket)?;
            }
        }

        // add redirect rules into transaction
        for ((anchor_name, redirect_rules), ticket) in
            redirect_changes.into_iter().zip(ticket_iterator.by_ref())
        {
            for redirect_rule in redirect_rules.iter() {
                Self::add_redirect_rule(fd, &anchor_name, redirect_rule, ticket)?;
            }
        }

        ioctl_guard!(ffi::pf_commit_trans(fd, &mut pfioc_trans))
    }

    /// Internal helper add filter rule into transaction
    fn add_filter_rule(fd: RawFd, anchor: &str, rule: &FilterRule, ticket: u32) -> Result<()> {
        // prepare pfioc_rule
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        pfioc_rule.action = ffi::pfvar::PF_CHANGE_NONE as u32;
        anchor
            .try_copy_to(&mut pfioc_rule.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
        rule.try_copy_to(&mut pfioc_rule.rule)?;

        // request new address pool
        let pool_ticket = utils::get_pool_ticket(fd)?;

        // setup address pool for route if routing is enabled on the rule.
        // Save the list so the memory is valid until end of method.
        let _pool_addr_list = if let Some(pool_addr) = rule.get_route().get_pool_addr() {
            // register pool address with firewall
            utils::add_pool_address(fd, pool_addr.clone(), pool_ticket)?;
            let pool_addr_list = PoolAddrList::new(&[pool_addr.clone()])
                .chain_err(|| ErrorKind::InvalidArgument("Invalid route target"))?;

            pfioc_rule.rule.rpool.list = unsafe { pool_addr_list.to_palist() };
            Some(pool_addr_list)
        } else {
            None
        };

        // fill in ticket with ticket associated with transaction
        pfioc_rule.ticket = ticket;
        pfioc_rule.pool_ticket = pool_ticket;

        // add rule into transaction
        ioctl_guard!(ffi::pf_add_rule(fd, &mut pfioc_rule))
    }

    /// Internal helper to add redirect rule into transaction
    fn add_redirect_rule(fd: RawFd, anchor: &str, rule: &RedirectRule, ticket: u32) -> Result<()> {
        // prepare pfioc_rule
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        anchor
            .try_copy_to(&mut pfioc_rule.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
        rule.try_copy_to(&mut pfioc_rule.rule)?;

        // register redirect address in newly created address pool
        let redirect_to = rule.get_redirect_to();
        let pool_ticket = utils::get_pool_ticket(fd)?;
        utils::add_pool_address(fd, redirect_to.ip(), pool_ticket)?;

        // copy address pool in pf_rule
        let redirect_pool = redirect_to.ip().to_pool_addr_list()?;
        pfioc_rule.rule.rpool.list = unsafe { redirect_pool.to_palist() };
        redirect_to.port().try_copy_to(&mut pfioc_rule.rule.rpool)?;

        // set tickets
        pfioc_rule.pool_ticket = pool_ticket;
        pfioc_rule.ticket = ticket;

        // add rule into transaction
        ioctl_guard!(ffi::pf_add_rule(fd, &mut pfioc_rule))
    }

    /// Internal helper to wire up pfioc_trans and pfioc_trans_e
    fn setup_trans(
        pfioc_trans: &mut ffi::pfvar::pfioc_trans,
        pfioc_trans_elements: &mut [ffi::pfvar::pfioc_trans_pfioc_trans_e],
    ) {
        pfioc_trans.size = pfioc_trans_elements.len() as i32;
        pfioc_trans.esize = mem::size_of::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() as i32;
        pfioc_trans.array = pfioc_trans_elements.as_mut_ptr();
    }

    /// Internal helper to initialize pfioc_trans_e
    fn new_trans_element(
        anchor: &str,
        ruleset_kind: RulesetKind,
    ) -> Result<ffi::pfvar::pfioc_trans_pfioc_trans_e> {
        let mut pfioc_trans_e = unsafe { mem::zeroed::<ffi::pfvar::pfioc_trans_pfioc_trans_e>() };
        pfioc_trans_e.rs_num = ruleset_kind.into();
        anchor
            .try_copy_to(&mut pfioc_trans_e.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
        Ok(pfioc_trans_e)
    }
}


/// Structure that describes anchor rules manipulation allowing for targeted changes in anchors.
/// The rules set to this structure will replace the active rules by transaction.
/// Not setting either of rules will leave active rules untouched by transaction.
/// In contrast, setting an empty vector for either of rules will remove the corresponding rules.
#[derive(Debug)]
pub struct AnchorChange {
    filter_rules: Option<Vec<FilterRule>>,
    redirect_rules: Option<Vec<RedirectRule>>,
}

impl AnchorChange {
    /// Returns an empty changeset
    pub fn new() -> Self {
        AnchorChange {
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
