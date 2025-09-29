// Copyright 2025 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use zerocopy::transmute_ref;

use crate::{Error, ErrorInternal, conversion::TryCopyTo};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceName(String);

impl AsRef<str> for InterfaceName {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
pub enum Interface {
    #[default]
    Any,
    Name(InterfaceName),
}

impl<T: AsRef<str>> From<T> for Interface {
    fn from(name: T) -> Self {
        Interface::Name(InterfaceName(name.as_ref().to_owned()))
    }
}

impl TryCopyTo<[i8]> for Interface {
    type Error = crate::Error;

    fn try_copy_to(&self, dst: &mut [i8]) -> Result<(), Self::Error> {
        match *self {
            Interface::Any => "",
            Interface::Name(InterfaceName(ref name)) => &name[..],
        }
        .try_copy_to(dst)
        .map_err(|reason| Error::from(ErrorInternal::InvalidInterfaceName(reason)))
    }
}

bitflags::bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct InterfaceFlags: i32 {
        /// Set or clear the skip flag on an interface.
        /// This is equivalent to PFI_IFLAG_SKIP.
        const SKIP = 0x0100;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InterfaceDescription {
    pub name: String,
    pub flags: InterfaceFlags,
}

impl TryFrom<crate::ffi::pfvar::pfi_kif> for InterfaceDescription {
    type Error = crate::Error;

    fn try_from(kif: crate::ffi::pfvar::pfi_kif) -> Result<Self, Self::Error> {
        let pfik_name: &[u8] = transmute_ref!(&kif.pfik_name[..]);
        let name = std::ffi::CStr::from_bytes_until_nul(pfik_name)
            .map_err(|_| Error::from(ErrorInternal::InvalidInterfaceName("missing nul byte")))?
            .to_str()
            .map_err(|_| Error::from(ErrorInternal::InvalidInterfaceName("invalid utf8 encoding")))?
            .to_owned();

        let flags = InterfaceFlags::from_bits_retain(kif.pfik_flags);

        Ok(InterfaceDescription { name, flags })
    }
}
