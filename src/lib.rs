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
extern crate lazy_static;

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::mem;

mod ffi;

mod rule;
pub use rule::*;

mod pooladdr;
pub use pooladdr::*;

mod anchor;
pub use anchor::*;

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
        }
        foreign_links {
            IoctlError(::std::io::Error);
        }
    }
}
pub use errors::*;


/// Macro for taking an expression with an ioctl call, perform it and return a Rust ´Result´.
macro_rules! ioctl_guard {
    ($func:expr) => {
        if unsafe { $func } == IOCTL_ERROR {
            let errno::Errno(error_code) = errno::errno();
            let io_error = io::Error::from_raw_os_error(error_code);
            let mut err = Err(ErrorKind::IoctlError(io_error).into());
            if error_code == libc::EEXIST {
                err = err.chain_err(|| ErrorKind::StateAlreadyActive);
            }
            err
        } else {
            Ok(()) as Result<()>
        }
    }
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
        fn copy_to(&self, dst: &mut T) -> ::Result<()>;
    }
}
use conversion::*;


/// Struct communicating with the PF firewall.
pub struct PfCtl {
    file: File,
}

impl PfCtl {
    /// Returns a new `PfCtl` if opening the PF device file succeeded.
    pub fn new() -> Result<Self> {
        let file = OpenOptions::new().read(true)
            .write(true)
            .open(PF_DEV_PATH)
            .chain_err(|| ErrorKind::DeviceOpenError(PF_DEV_PATH))?;
        Ok(PfCtl { file: file })
    }

    /// Tries to enable PF. If the firewall is already enabled it will return an
    /// `StateAlreadyActive` error. If there is some other error it will return an `IoctlError`.
    pub fn enable(&mut self) -> Result<()> {
        ioctl_guard!(ffi::pf_start(self.fd()))
    }

    /// Tries to disable PF. If the firewall is already disabled it will return an
    /// `StateAlreadyActive` error. If there is some other error it will return an `IoctlError`.
    pub fn disable(&mut self) -> Result<()> {
        ioctl_guard!(ffi::pf_stop(self.fd()))
    }

    /// Tries to determine if PF is enabled or not.
    pub fn is_enabled(&mut self) -> Result<bool> {
        let mut pf_status = unsafe { mem::zeroed::<ffi::pfvar::pf_status>() };
        ioctl_guard!(ffi::pf_get_status(self.fd(), &mut pf_status))?;
        Ok(pf_status.running == 1)
    }

    pub fn add_anchor<S: AsRef<str>>(&mut self, name: S, kind: AnchorKind) -> Result<()> {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };

        pfioc_rule.rule.action = kind.into();
        name.copy_to(&mut pfioc_rule.anchor_call[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;

        ioctl_guard!(ffi::pf_insert_rule(self.fd(), &mut pfioc_rule))?;
        Ok(())
    }

    // TODO(linus): Make more generic. No hardcoded ADD_TAIL etc.
    pub fn add_rule<S: AsRef<str>>(&mut self, anchor: S, rule: &FilterRule) -> Result<()> {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };

        pfioc_rule.pool_ticket = self.get_pool_ticket(&anchor)?;
        pfioc_rule.ticket = self.get_ticket(&anchor)?;
        anchor.copy_to(&mut pfioc_rule.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
        rule.copy_to(&mut pfioc_rule.rule)?;

        pfioc_rule.action = ffi::pfvar::PF_CHANGE_ADD_TAIL as u32;
        ioctl_guard!(ffi::pf_change_rule(self.fd(), &mut pfioc_rule))?;
        Ok(())
    }

    fn get_pool_ticket<S: AsRef<str>>(&self, anchor: S) -> Result<u32> {
        let mut pfioc_pooladdr = unsafe { mem::zeroed::<ffi::pfvar::pfioc_pooladdr>() };
        pfioc_pooladdr.action = ffi::pfvar::PF_CHANGE_GET_TICKET as u32;
        anchor.copy_to(&mut pfioc_pooladdr.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
        ioctl_guard!(ffi::pf_begin_addrs(self.fd(), &mut pfioc_pooladdr))?;
        Ok(pfioc_pooladdr.ticket)
    }

    fn get_ticket<S: AsRef<str>>(&self, anchor: S) -> Result<u32> {
        let mut pfioc_rule = unsafe { mem::zeroed::<ffi::pfvar::pfioc_rule>() };
        pfioc_rule.action = ffi::pfvar::PF_CHANGE_GET_TICKET as u32;
        anchor.copy_to(&mut pfioc_rule.anchor[..])
            .chain_err(|| ErrorKind::InvalidArgument("Invalid anchor name"))?;
        ioctl_guard!(ffi::pf_change_rule(self.fd(), &mut pfioc_rule))?;
        Ok(pfioc_rule.ticket)
    }

    /// Internal function for getting the raw file descriptor to PF.
    fn fd(&self) -> ::std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        self.file.as_raw_fd()
    }
}
