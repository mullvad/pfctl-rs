// Copyright 2017 Amagicom AB.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use Result;
use conversion::TryCopyTo;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Interface {
    Any,
    Name(String),
}

impl Default for Interface {
    fn default() -> Self {
        Interface::Any
    }
}

impl<T: AsRef<str>> From<T> for Interface {
    fn from(name: T) -> Self {
        Interface::Name(name.as_ref().to_owned())
    }
}

impl TryCopyTo<[i8]> for Interface {
    fn copy_to(&self, dst: &mut [i8]) -> Result<()> {
        match *self {
                Interface::Any => "",
                Interface::Name(ref name) => &name[..],
            }
            .copy_to(dst)
    }
}
