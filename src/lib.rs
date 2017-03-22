#[macro_use]
extern crate ioctl_sys;
#[macro_use]
extern crate error_chain;
extern crate errno;
extern crate libc;

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::mem;

pub mod ffi;

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
            StateAlreadyActive {
                description("Target state is already active")
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

    /// Internal function for getting the raw file descriptor to PF.
    fn fd(&self) -> ::std::os::unix::io::RawFd {
        use std::os::unix::io::AsRawFd;
        self.file.as_raw_fd()
    }
}
