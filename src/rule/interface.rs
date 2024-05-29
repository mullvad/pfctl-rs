// Copyright 2024 Mullvad VPN AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use crate::{conversion::TryCopyTo, Result};

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
    fn try_copy_to(&self, dst: &mut [i8]) -> Result<()> {
        match *self {
            Interface::Any => "",
            Interface::Name(InterfaceName(ref name)) => &name[..],
        }
        .try_copy_to(dst)
    }
}
