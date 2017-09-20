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
//!     .action(pfctl::FilterRuleAction::Pass)
//!     .interface("lo0")
//!     .build()
//!     .unwrap();
//!
//! // Add the filterig rule to the anchor we just created.
//! pf.add_rule(anchor_name, &rule).unwrap();
//! ```
//!

#[macro_use]
extern crate derive_builder;
extern crate errno;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate ioctl_sys;
extern crate ipnetwork;
extern crate libc;

#[cfg(test)]
#[macro_use]
extern crate assert_matches;

#[cfg(test)]
#[macro_use]
extern crate lazy_static;

use std::ffi::CStr;
use std::fs::File;
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

mod ffi;

#[macro_use]
mod macros;
mod utils;

mod rule;
pub use rule::*;

mod pooladdr;
pub use pooladdr::*;

mod anchor;
pub use anchor::*;

mod ruleset;
pub use ruleset::*;

mod transaction;
pub use transaction::*;

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


/// Delay between retries
const RETRY_IF_BUSY_DELAY: u64 = 100;

/// Maximum number of retries to perform before giving up
const RETRY_IF_BUSY_MAX: i8 = 5;

/// Helper function that runs the given closure if received error indicates that firewall rules
/// were modified concurrently by other program until either timeout, or number of retries reached,
/// or any other result occurred.
pub fn retry_if_busy<F, R>(f: F) -> Result<R>
where
    F: Fn() -> Result<R>,
{
    let mut retry = 0;
    loop {
        match f() {
            Err(Error(ErrorKind::IoctlError(ref io_err), _))
                if io_err.raw_os_error() == Some(libc::EBUSY) && retry < RETRY_IF_BUSY_MAX =>
            {
                retry += 1;
                ::std::thread::sleep(Duration::from_millis(RETRY_IF_BUSY_DELAY));
            }
            r => return r,
        }
    }
}


/// Module for types and traits dealing with translating between Rust and FFI.
mod conversion {
    /// Internal trait for all types that can write their value into another type without risk
    /// of failing.
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
        let file = utils::open_pf()?;
        Ok(PfCtl { file: file })
    }

    /// Tries to enable PF. If the firewall is already enabled it will return an
    /// `StateAlreadyActive` error. If there is some other error it will return an `IoctlError`.
    pub fn enable(&mut self) -> Result<()> {
        ioctl_guard!(ffi::pf_start(self.fd()))
    }

    /// Same as `enable`, but `StateAlreadyActive` errors are supressed and exchanged for
    /// `Ok(())`.
    pub fn try_enable(&mut self) -> Result<()> {
        ignore_error_kind!(self.enable(), ErrorKind::StateAlreadyActive)
    }

    /// Tries to disable PF. If the firewall is already disabled it will return an
    /// `StateAlreadyActive` error. If there is some other error it will return an `IoctlError`.
    pub fn disable(&mut self) -> Result<()> {
        ioctl_guard!(ffi::pf_stop(self.fd()), libc::ENOENT)
    }

    /// Same as `disable`, but `StateAlreadyActive` errors are supressed and exchanged for
    /// `Ok(())`.
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
        self.with_anchor_rule(name, kind, |mut anchor_rule| {
            ioctl_guard!(ffi::pf_delete_rule(self.fd(), &mut anchor_rule))
        })
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

        pfioc_rule.pool_ticket = utils::get_pool_ticket(self.fd(), anchor)?;
        pfioc_rule.ticket = utils::get_ticket(self.fd(), &anchor, AnchorKind::Filter)?;
        anchor
            .try_copy_to(&mut pfioc_rule.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
        rule.try_copy_to(&mut pfioc_rule.rule)?;

        pfioc_rule.action = ffi::pfvar::PF_CHANGE_ADD_TAIL as u32;
        ioctl_guard!(ffi::pf_change_rule(self.fd(), &mut pfioc_rule))
    }

    pub fn set_rules(&mut self, anchor: &str, change: AnchorChange) -> Result<()> {
        let mut trans = Transaction::new();
        trans.add_change(anchor, change);
        trans.commit()
    }

    pub fn add_redirect_rule(&mut self, anchor: &str, rule: &RedirectRule) -> Result<()> {
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
        pfioc_rule.ticket = utils::get_ticket(self.fd(), anchor, AnchorKind::Redirect)?;

        // append rule
        pfioc_rule.action = ffi::pfvar::PF_CHANGE_ADD_TAIL as u32;
        ioctl_guard!(ffi::pf_change_rule(self.fd(), &mut pfioc_rule))
    }

    pub fn flush_rules(&mut self, anchor: &str, kind: RulesetKind) -> Result<()> {
        let mut trans = Transaction::new();
        let mut anchor_change = AnchorChange::new();
        match kind {
            RulesetKind::Filter => anchor_change.set_filter_rules(Vec::new()),
            RulesetKind::Redirect => anchor_change.set_redirect_rules(Vec::new()),
        };
        trans.add_change(anchor, anchor_change);
        trans.commit()
    }

    /// Clear states created by rules in anchor.
    /// Returns total number of removed states upon success, otherwise
    /// ErrorKind::AnchorDoesNotExist if anchor does not exist.
    pub fn clear_states(&mut self, anchor_name: &str, kind: AnchorKind) -> Result<u32> {
        let pfsync_states = self.get_states()?;
        if pfsync_states.len() > 0 {
            self.with_anchor_rule(anchor_name, kind, |anchor_rule| {
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
            })
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
    where
        F: FnOnce(ffi::pfvar::pfioc_rule) -> Result<R>,
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

    /// Internal function for getting the raw file descriptor to PF.
    fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}


/// Creates pfioc_states and returns a tuple of pfioc_states and vector of pfsync_state with the
/// given number of elements.
/// Since pfioc_states uses raw memory pointer to Vec<pfsync_state>, make sure that
/// Vec<pfsync_state> outlives pfsync_states.
fn setup_pfioc_states(
    num_states: u32,
) -> (ffi::pfvar::pfioc_states, Vec<ffi::pfvar::pfsync_state>) {
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
fn setup_pfioc_state_kill(
    pfsync_state: &ffi::pfvar::pfsync_state,
    pfioc_state_kill: &mut ffi::pfvar::pfioc_state_kill,
) {
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
