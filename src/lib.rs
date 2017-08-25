// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Library for interfacing with the Packet Filter (PF) firewall on macOS.
//!
//! Allows controlling the PF firewall on macOS through ioctl syscalls and the `/dev/pf` device.
//!
//! PF is the firewall used in most (all?) BSD systems, but this crate only supports the macOS
//! variant for now. If it can be made to work on more BSD systems that would be great, but no work
//! has been put into that so far.
//!
//! Reading and writing to `/dev/pf` requires root permissions. So any program using this crate
//! must run as the superuser, otherwise creating the `PfCtl` instance will fail with a
//! "Permission denied" error.
//!
//! # Usage and examples
//!
//! A lot of examples of how to use the various features of this crate can be found in the
//! integration tests in `tests/`.
//!
//! Here is a simple example showing how to enable the firewall and add a packet filtering rule:
//!
//! ```no_run
//! extern crate pfctl;
//!
//! // Create a PfCtl instance to control PF with:
//! let mut pf = pfctl::PfCtl::new().unwrap();
//!
//! // Enable the firewall, equivalent to the command "pfctl -e":
//! pf.try_enable().unwrap();
//!
//! // Add an anchor rule for packet filtering rules into PF. This will fail if it already exists,
//! // use `try_add_anchor` to avoid that:
//! let anchor_name = "testing-out-pfctl";
//! pf.add_anchor(anchor_name, pfctl::AnchorKind::Filter).unwrap();
//!
//! // Create a packet filtering rule matching all packets on the "lo0" interface and allowing
//! // them to pass:
//! let rule = pfctl::FilterRuleBuilder::default()
//!     .action(pfctl::RuleAction::Pass)
//!     .interface("lo0")
//!     .build()
//!     .unwrap();
//!
//! // Add the filterig rule to the anchor we just created.
//! pf.add_rule(anchor_name, &rule).unwrap();
//! ```
//!

#[macro_use]
extern crate ioctl_sys;
#[macro_use]
extern crate error_chain;
extern crate errno;
#[macro_use]
extern crate derive_builder;
extern crate libc;
extern crate ipnetwork;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

use std::ffi::CStr;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};

mod ffi;

mod rule;
pub use rule::*;

mod pooladdr;
pub use pooladdr::*;

mod anchor;
pub use anchor::*;

mod ruleset;
pub use ruleset::*;

/// The path to the PF device file this library will use to communicate with PF.
pub const PF_DEV_PATH: &'static str = "/dev/pf";

const IOCTL_ERROR: i32 = -1;

mod errors {
    error_chain! {
        errors {
            DeviceOpenError(s: &'static str) {
                description("Unable to open PF device file")
                display("Unable to open PF device file at '{}'", s)
            }
            InvalidArgument(s: &'static str) {
                display("Invalid argument: {}", s)
            }
            StateAlreadyActive {
                description("Target state is already active")
            }
            InvalidRuleCombination(s: String) {
                description("Rule contains incompatible values")
                display("Incompatible values in rule: {}", s)
            }
            AnchorDoesNotExist {
                display("Anchor does not exist")
            }
        }
        foreign_links {
            IoctlError(::std::io::Error);
        }
    }
}
pub use errors::*;


/// Macro for taking an expression with an ioctl call, perform it and return a Rust ´Result´.
macro_rules! ioctl_guard {
    ($func:expr) => (ioctl_guard!($func, libc::EEXIST));
    ($func:expr, $already_active:expr) => {
        if unsafe { $func } == IOCTL_ERROR {
            let errno::Errno(error_code) = errno::errno();
            let io_error = io::Error::from_raw_os_error(error_code);
            let mut err = Err(ErrorKind::IoctlError(io_error).into());
            if error_code == $already_active {
                err = err.chain_err(|| ErrorKind::StateAlreadyActive);
            }
            err
        } else {
            Ok(()) as Result<()>
        }
    }
}

/// Returns the given input result, except if it is an `Err` matching the given `ErrorKind`,
/// then it returns `Ok(())` instead, so the error is ignored.
macro_rules! ignore_error_kind {
    ($result:expr, $kind:pat) => {
        match $result {
            Err($crate::Error($kind, _)) => Ok(()),
            result => result,
        }
    }
}

/// Open PF virtual device
fn open_pf() -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(PF_DEV_PATH)
        .chain_err(|| ErrorKind::DeviceOpenError(PF_DEV_PATH))
}

/// Get pool ticket
fn get_pool_ticket(fd: RawFd, anchor: &str) -> Result<u32> {
    let mut pfioc_pooladdr = unsafe { mem::zeroed::<ffi::pfvar::pfioc_pooladdr>() };
    pfioc_pooladdr.action = ffi::pfvar::PF_CHANGE_GET_TICKET as u32;
    anchor
        .try_copy_to(&mut pfioc_pooladdr.anchor[..])
        .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
    ioctl_guard!(ffi::pf_begin_addrs(fd, &mut pfioc_pooladdr))?;
    Ok(pfioc_pooladdr.ticket)
}


/// Module for types and traits dealing with translating between Rust and FFI.
mod conversion {
    /// Internal trait for all types that can write their value into another type without risk of
    /// failing.
    pub trait CopyTo<T: ?Sized> {
        fn copy_to(&self, dst: &mut T);
    }

    /// Internal trait for all types that can try to write their value into another type.
    pub trait TryCopyTo<T: ?Sized> {
        fn try_copy_to(&self, dst: &mut T) -> ::Result<()>;
    }
}
use conversion::*;


/// Internal function to safely compare Rust string with raw C string slice
fn compare_cstr_safe(s: &str, cchars: &[std::os::raw::c_char]) -> Result<bool> {
    ensure!(cchars.iter().any(|&c| c == 0), "Not null terminated");
    let cs = unsafe { CStr::from_ptr(cchars.as_ptr()) };
    Ok(s.as_bytes() == cs.to_bytes())
}


/// Struct communicating with the PF firewall.
pub struct PfCtl {
    file: File,
}

impl PfCtl {
    /// Returns a new `PfCtl` if opening the PF device file succeeded.
    pub fn new() -> Result<Self> {
        let file = open_pf()?;
        Ok(PfCtl { file: file })
    }

    /// Tries to enable PF. If the firewall is already enabled it will return an
    /// `StateAlreadyActive` error. If there is some other error it will return an `IoctlError`.
    pub fn enable(&mut self) -> Result<()> {
        ioctl_guard!(ffi::pf_start(self.fd()))
    }

    /// Same as `enable`, but `StateAlreadyActive` errors are supressed and exchanged for `Ok(())`.
    pub fn try_enable(&mut self) -> Result<()> {
        ignore_error_kind!(self.enable(), ErrorKind::StateAlreadyActive)
    }

    /// Tries to disable PF. If the firewall is already disabled it will return an
    /// `StateAlreadyActive` error. If there is some other error it will return an `IoctlError`.
    pub fn disable(&mut self) -> Result<()> {
        ioctl_guard!(ffi::pf_stop(self.fd()), libc::ENOENT)
    }

    /// Same as `disable`, but `StateAlreadyActive` errors are supressed and exchanged for `Ok(())`.
    pub fn try_disable(&mut self) -> Result<()> {
        ignore_error_kind!(self.disable(), ErrorKind::StateAlreadyActive)
    }

    /// Tries to determine if PF is enabled or not.
    pub fn is_enabled(&mut self) -> Result<bool> {
        let mut pf_status = unsafe { mem::zeroed::<ffi::pfvar::pf_status>() };
        ioctl_guard!(ffi::pf_get_status(self.fd(), &mut pf_status))?;
        Ok(pf_status.running == 1)
    }

    pub fn add_anchor(&mut self, name: &str, kind: AnchorKind) -> Result<()> {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };

        pfioc_rule.rule.action = kind.into();
        name.try_copy_to(&mut pfioc_rule.anchor_call[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;

        ioctl_guard!(ffi::pf_insert_rule(self.fd(), &mut pfioc_rule))?;
        Ok(())
    }

    /// Same as `add_anchor`, but `StateAlreadyActive` errors are supressed and exchanged for
    /// `Ok(())`.
    pub fn try_add_anchor(&mut self, name: &str, kind: AnchorKind) -> Result<()> {
        ignore_error_kind!(self.add_anchor(name, kind), ErrorKind::StateAlreadyActive)
    }

    pub fn remove_anchor(&mut self, name: &str, kind: AnchorKind) -> Result<()> {
        self.with_anchor_rule(
            name,
            kind,
            |mut anchor_rule| ioctl_guard!(ffi::pf_delete_rule(self.fd(), &mut anchor_rule)),
        )
    }

    /// Same as `remove_anchor`, but `AnchorDoesNotExist` errors are supressed and exchanged for
    /// `Ok(())`.
    pub fn try_remove_anchor(&mut self, name: &str, kind: AnchorKind) -> Result<()> {
        ignore_error_kind!(
            self.remove_anchor(name, kind),
            ErrorKind::AnchorDoesNotExist
        )
    }

    // TODO(linus): Make more generic. No hardcoded ADD_TAIL etc.
    pub fn add_rule(&mut self, anchor: &str, rule: &FilterRule) -> Result<()> {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };

        pfioc_rule.pool_ticket = get_pool_ticket(self.fd(), anchor)?;
        pfioc_rule.ticket = self.get_ticket(&anchor, AnchorKind::Filter)?;
        anchor
            .try_copy_to(&mut pfioc_rule.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
        rule.try_copy_to(&mut pfioc_rule.rule)?;

        pfioc_rule.action = ffi::pfvar::PF_CHANGE_ADD_TAIL as u32;
        ioctl_guard!(ffi::pf_change_rule(self.fd(), &mut pfioc_rule))?;
        Ok(())
    }

    pub fn set_rules(&mut self, anchor: &str, rules: &[FilterRule]) -> Result<()> {
        let trans = Transaction::new(&anchor, RulesetKind::Filter)?;
        trans.add_rules(rules)?;
        trans.commit()
    }

    pub fn flush_rules(&mut self, anchor: &str, kind: RulesetKind) -> Result<()> {
        Transaction::new(&anchor, kind)?.commit()
    }

    /// Clear states created by rules in anchor.
    /// Returns total number of removed states upon success, otherwise
    /// ErrorKind::AnchorDoesNotExist if anchor does not exist.
    pub fn clear_states(&mut self, anchor_name: &str, kind: AnchorKind) -> Result<u32> {
        let pfsync_states = self.get_states()?;
        if pfsync_states.len() > 0 {
            self.with_anchor_rule(
                anchor_name, kind, |anchor_rule| {
                    pfsync_states
                    .iter()
                    .filter(|pfsync_state| pfsync_state.anchor == anchor_rule.nr)
                    .map(|pfsync_state| {
                        let mut pfioc_state_kill =
                            unsafe { mem::zeroed::<ffi::pfvar::pfioc_state_kill>() };
                        setup_pfioc_state_kill(&pfsync_state, &mut pfioc_state_kill);
                        ioctl_guard!(ffi::pf_kill_states(self.fd(), &mut pfioc_state_kill))?;
                        // psk_af holds the number of killed states
                        Ok(pfioc_state_kill.psk_af as u32)
                    })
                    .collect::<Result<Vec<_>>>()
                    .map(|v| v.iter().sum())
                }
            )
        } else {
            Ok(0)
        }
    }

    /// Get all states created by stateful rules
    fn get_states(&mut self) -> Result<Vec<ffi::pfvar::pfsync_state>> {
        let num_states = self.get_num_states()?;
        if num_states > 0 {
            let (mut pfioc_states, pfsync_states) = setup_pfioc_states(num_states);
            ioctl_guard!(ffi::pf_get_states(self.fd(), &mut pfioc_states))?;
            Ok(pfsync_states)
        } else {
            Ok(vec![])
        }
    }

    /// Helper function to find an anchor in main ruleset matching by name and kind.
    ///
    /// Calls closure with anchor rule (`pfioc_rule`) on match.
    /// Provided `pfioc_rule` can be used to modify or remove the anchor rule.
    /// The return value from closure is transparently passed to the caller.
    ///
    /// - Returns Result<R> from call to closure on match.
    /// - Returns `ErrorKind::AnchorDoesNotExist` on mismatch, the closure is not called in that
    /// case.
    fn with_anchor_rule<F, R>(&self, name: &str, kind: AnchorKind, f: F) -> Result<R>
        where F: FnOnce(ffi::pfvar::pfioc_rule) -> Result<R>
    {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        pfioc_rule.rule.action = kind.into();
        ioctl_guard!(ffi::pf_get_rules(self.fd(), &mut pfioc_rule))?;
        pfioc_rule.action = ffi::pfvar::PF_GET_NONE as u32;
        for i in 0..pfioc_rule.nr {
            pfioc_rule.nr = i;
            ioctl_guard!(ffi::pf_get_rule(self.fd(), &mut pfioc_rule))?;
            if compare_cstr_safe(name, &pfioc_rule.anchor_call)? {
                return f(pfioc_rule);
            }
        }
        bail!(ErrorKind::AnchorDoesNotExist);
    }

    /// Returns global number of states created by all stateful rules (see keep_state)
    fn get_num_states(&self) -> Result<u32> {
        let mut pfioc_states = unsafe { mem::zeroed::<ffi::pfvar::pfioc_states>() };
        ioctl_guard!(ffi::pf_get_states(self.fd(), &mut pfioc_states))?;
        let element_size = mem::size_of::<ffi::pfvar::pfsync_state>() as u32;
        let buffer_size = pfioc_states.ps_len as u32;
        Ok(buffer_size / element_size)
    }

    fn get_ticket(&self, anchor: &str, kind: AnchorKind) -> Result<u32> {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        pfioc_rule.action = ffi::pfvar::PF_CHANGE_GET_TICKET as u32;
        pfioc_rule.rule.action = kind.into();
        anchor
            .try_copy_to(&mut pfioc_rule.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
        ioctl_guard!(ffi::pf_change_rule(self.fd(), &mut pfioc_rule))?;
        Ok(pfioc_rule.ticket)
    }

    /// Internal function for getting the raw file descriptor to PF.
    fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}


#[derive(Debug)]
struct Transaction {
    file: File,
    ticket: u32,
    kind: RulesetKind,
    anchor: String,
}

impl Transaction {
    /// Returns a new `Transaction` if opening the PF device file succeeded.
    pub fn new(anchor: &str, kind: RulesetKind) -> Result<Self> {
        let file = open_pf()?;
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
        pfioc_rule.pool_ticket = get_pool_ticket(self.fd(), &self.anchor)?;
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

/// Creates pfioc_states and returns a tuple of pfioc_states and vector of pfsync_state with the
/// given number of elements.
/// Since pfioc_states uses raw memory pointer to Vec<pfsync_state>, make sure that
/// Vec<pfsync_state> outlives pfsync_states.
fn setup_pfioc_states(num_states: u32)
                      -> (ffi::pfvar::pfioc_states, Vec<ffi::pfvar::pfsync_state>) {
    let mut pfioc_states = unsafe { mem::zeroed::<ffi::pfvar::pfioc_states>() };
    let element_size = mem::size_of::<ffi::pfvar::pfsync_state>() as i32;
    pfioc_states.ps_len = element_size * (num_states as i32);
    let mut pfsync_states = (0..num_states)
        .map(|_| unsafe { mem::zeroed::<ffi::pfvar::pfsync_state>() })
        .collect::<Vec<_>>();
    unsafe {
        *pfioc_states.ps_u.psu_states.as_mut() = pfsync_states.as_mut_ptr();
    }
    (pfioc_states, pfsync_states)
}

/// Setup pfioc_state_kill from pfsync_state
fn setup_pfioc_state_kill(pfsync_state: &ffi::pfvar::pfsync_state,
                          pfioc_state_kill: &mut ffi::pfvar::pfioc_state_kill) {
    pfioc_state_kill.psk_af = pfsync_state.af_lan;
    pfioc_state_kill.psk_proto = pfsync_state.proto;
    pfioc_state_kill.psk_proto_variant = pfsync_state.proto_variant;
    pfioc_state_kill.psk_ifname = pfsync_state.ifname;
    unsafe {
        pfioc_state_kill.psk_src.addr.v.a.as_mut().addr = pfsync_state.lan.addr;
        pfioc_state_kill.psk_dst.addr.v.a.as_mut().addr = pfsync_state.ext_lan.addr;
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn compare_cstr_without_nul() {
        let cstr = CString::new("Hello").unwrap();
        let cchars: &[i8] = unsafe { mem::transmute(cstr.as_bytes()) };
        assert_matches!(
            compare_cstr_safe("Hello", cchars),
            Err(ref e) if e.description() == "Not null terminated"
        );
    }

    #[test]
    fn compare_same_strings() {
        let cstr = CString::new("Hello").unwrap();
        let cchars: &[i8] = unsafe { mem::transmute(cstr.as_bytes_with_nul()) };
        assert_matches!(compare_cstr_safe("Hello", cchars), Ok(true));
    }

    #[test]
    fn compare_different_strings() {
        let cstr = CString::new("Hello").unwrap();
        let cchars: &[i8] = unsafe { mem::transmute(cstr.as_bytes_with_nul()) };
        assert_matches!(compare_cstr_safe("olleH", cchars), Ok(false));
    }

    #[test]
    fn compare_long_short_strings() {
        let cstr = CString::new("veryverylong").unwrap();
        let cchars: &[i8] = unsafe { mem::transmute(cstr.as_bytes_with_nul()) };
        assert_matches!(compare_cstr_safe("short", cchars), Ok(false));
    }

    #[test]
    fn compare_short_long_strings() {
        let cstr = CString::new("short").unwrap();
        let cchars: &[i8] = unsafe { mem::transmute(cstr.as_bytes_with_nul()) };
        assert_matches!(compare_cstr_safe("veryverylong", cchars), Ok(false));
    }
}
